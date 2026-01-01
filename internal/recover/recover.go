package recover

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hashicorp/vault/shamir"

	"github.com/wildy/ssssecret/internal/cryptox"
	"github.com/wildy/ssssecret/internal/qrpayload"
)

type DocSummary struct {
	DocID            string
	CipherChunksHave int
	CipherChunksNeed int
	SharesHave       int
	SharesNeed       int
	Comp             string
}

type RecoveryResult struct {
	DocID  string
	Secret []byte
	Comp   string
}

// ParseAndGroup parses QR payload JSON texts and groups by doc id.
func ParseAndGroup(payloads []string) (map[string]*Grouped, error) {
	out := map[string]*Grouped{}
	for _, p := range payloads {
		typ, err := qrpayload.UnmarshalType(p)
		if err != nil {
			continue
		}
		switch typ {
		case qrpayload.TypeCipherChunk:
			var c qrpayload.CipherChunkV1
			if err := json.Unmarshal([]byte(p), &c); err != nil {
				continue
			}
			g := out[c.Doc]
			if g == nil {
				g = &Grouped{DocID: c.Doc}
				out[c.Doc] = g
			}
			g.addCipher(&c)
		case qrpayload.TypeShare:
			var s qrpayload.ShareV1
			if err := json.Unmarshal([]byte(p), &s); err != nil {
				continue
			}
			g := out[s.Doc]
			if g == nil {
				g = &Grouped{DocID: s.Doc}
				out[s.Doc] = g
			}
			g.addShare(&s)
		default:
			continue
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid payloads found")
	}
	return out, nil
}

type Grouped struct {
	DocID string

	// From ciphertext chunks:
	KDF   string
	AEAD  string
	Comp  string
	N     int
	T     int
	Salt  []byte
	Nonce []byte

	ChunksTotal int
	Chunks      map[int][]byte // 1-based index -> chunk bytes

	Shares [][]byte
}

func (g *Grouped) addCipher(c *qrpayload.CipherChunkV1) {
	if g.Chunks == nil {
		g.Chunks = map[int][]byte{}
	}
	if g.KDF == "" {
		g.KDF = c.KDF
		g.AEAD = c.AEAD
		g.Comp = c.Comp
		g.N = c.N
		g.T = c.T
		g.ChunksTotal = c.ChunkTotal
		g.Salt, _ = base64.StdEncoding.DecodeString(c.SaltB64)
		g.Nonce, _ = base64.StdEncoding.DecodeString(c.NonceB64)
	}
	// Always record chunk if decodes.
	b, err := base64.StdEncoding.DecodeString(c.DataB64)
	if err != nil {
		return
	}
	if _, exists := g.Chunks[c.ChunkIndex]; !exists {
		g.Chunks[c.ChunkIndex] = b
	}
	if c.ChunkTotal > g.ChunksTotal {
		g.ChunksTotal = c.ChunkTotal
	}
}

func (g *Grouped) addShare(s *qrpayload.ShareV1) {
	b, err := base64.StdEncoding.DecodeString(s.ShareB64)
	if err != nil {
		return
	}
	g.Shares = append(g.Shares, b)
	if g.N == 0 {
		g.N = s.N
	}
	if g.T == 0 {
		g.T = s.T
	}
}

func Summaries(groups map[string]*Grouped) []DocSummary {
	var out []DocSummary
	for _, g := range groups {
		needChunks := g.ChunksTotal
		if needChunks == 0 {
			needChunks = guessChunksTotal(g.Chunks)
		}
		needShares := g.T
		if needShares == 0 {
			needShares = 0
		}
		out = append(out, DocSummary{
			DocID:            g.DocID,
			CipherChunksHave: len(g.Chunks),
			CipherChunksNeed: needChunks,
			SharesHave:       len(g.Shares),
			SharesNeed:       needShares,
			Comp:             g.Comp,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DocID < out[j].DocID })
	return out
}

func RecoverSecret(g *Grouped) (*RecoveryResult, error) {
	if g == nil {
		return nil, fmt.Errorf("group is nil")
	}
	if g.T <= 0 || g.N <= 0 {
		return nil, fmt.Errorf("missing n/t")
	}
	if len(g.Shares) < g.T {
		return nil, fmt.Errorf("need %d shares, have %d", g.T, len(g.Shares))
	}
	if g.ChunksTotal > 0 && len(g.Chunks) < g.ChunksTotal {
		return nil, fmt.Errorf("need %d ciphertext chunks, have %d", g.ChunksTotal, len(g.Chunks))
	}
	if len(g.Nonce) != cryptox.NonceSize {
		return nil, fmt.Errorf("invalid nonce")
	}
	if len(g.Salt) == 0 {
		return nil, fmt.Errorf("missing salt")
	}

	// Combine shares to recover X.
	x, err := shamir.Combine(g.Shares[:g.T])
	if err != nil {
		return nil, err
	}
	key, err := cryptox.DeriveAES256Key(x, g.Salt)
	if err != nil {
		return nil, err
	}

	ct, err := g.reassembleCiphertext()
	if err != nil {
		return nil, err
	}

	env := &cryptox.AEADEnvelope{Nonce: g.Nonce, Ciphertext: ct}
	compressed, err := cryptox.DecryptAES256GCM(env, key, []byte(g.DocID))
	if err != nil {
		return nil, err
	}

	plain := compressed
	switch g.Comp {
	case "", "none":
		// ok
	case "gzip":
		plain, err = cryptox.DecompressGzip(compressed)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported compression: %q", g.Comp)
	}

	return &RecoveryResult{DocID: g.DocID, Secret: plain, Comp: g.Comp}, nil
}

func (g *Grouped) reassembleCiphertext() ([]byte, error) {
	if len(g.Chunks) == 0 {
		return nil, fmt.Errorf("no ciphertext chunks")
	}
	total := g.ChunksTotal
	if total <= 0 {
		total = guessChunksTotal(g.Chunks)
	}
	var buf bytes.Buffer
	for i := 1; i <= total; i++ {
		c, ok := g.Chunks[i]
		if !ok {
			return nil, fmt.Errorf("missing ciphertext chunk %d/%d", i, total)
		}
		buf.Write(c)
	}
	return buf.Bytes(), nil
}

func guessChunksTotal(chunks map[int][]byte) int {
	max := 0
	for k := range chunks {
		if k > max {
			max = k
		}
	}
	return max
}


