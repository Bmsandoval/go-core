// Package fuzzy is a small, dependency-free fzf-style fuzzy finder: a
// case-insensitive subsequence matcher with fzf's scoring model (bonuses for
// word boundaries, camelCase humps, and consecutive runs; penalties for gaps),
// plus a generic ranked Filter over any slice.
//
// It is a faithful port of junegunn/fzf's FuzzyMatchV1 scoring — the same
// constants and bonus rules — so ranking matches the muscle memory of anyone
// who has used fzf. Use it to power "type to filter" UIs, command palettes, and
// search boxes where a pattern is a subsequence of the candidate text.
//
// This is the canonical fuzzy-find implementation shared across the prototype
// factory; the php-core (Bmsandoval\PhpCore\Search) and react-core (search/)
// versions mirror this scoring so results rank identically across stacks.
package fuzzy

import (
	"sort"
	"unicode"
)

// fzf scoring constants (junegunn/fzf, algo.go).
const (
	scoreMatch        = 16
	scoreGapStart     = -3
	scoreGapExtension = -1

	bonusBoundary = scoreMatch / 2          // start of a word / after a separator
	bonusNonWord  = scoreMatch / 2          // matching a non-word char itself
	bonusCamel123 = bonusBoundary + scoreGapExtension
	// Consecutive matches: cancel the gap penalty they would otherwise imply.
	bonusConsecutive = -(scoreGapStart + scoreGapExtension)
	// White/delimiter boundaries score a touch higher than a plain boundary.
	bonusBoundaryWhite     = bonusBoundary + 2
	bonusBoundaryDelimiter = bonusBoundary + 1

	// The first matched char's boundary bonus is doubled.
	bonusFirstCharMultiplier = 2
)

type charClass int

const (
	classWhite charClass = iota
	classNonWord
	classDelimiter
	classLower
	classUpper
	classLetter
	classNumber
)

// delimiters that get a slightly higher boundary bonus (paths, snake_case, etc.).
func isDelimiter(r rune) bool {
	switch r {
	case '/', ',', ':', ';', '_', '-', '.', ' ':
		return true
	}
	return false
}

func classOf(r rune) charClass {
	switch {
	case unicode.IsLower(r):
		return classLower
	case unicode.IsUpper(r):
		return classUpper
	case unicode.IsNumber(r):
		return classNumber
	case unicode.IsLetter(r):
		return classLetter
	case unicode.IsSpace(r):
		return classWhite
	case isDelimiter(r):
		return classDelimiter
	default:
		return classNonWord
	}
}

func bonusFor(prev, cur charClass) int {
	if cur > classNonWord {
		// Transition from a boundary into a word char.
		switch prev {
		case classWhite:
			return bonusBoundaryWhite
		case classDelimiter:
			return bonusBoundaryDelimiter
		case classNonWord:
			return bonusBoundary
		}
	}
	// camelCase hump (lower->Upper) or letter->number boundary.
	if (prev == classLower && cur == classUpper) ||
		(prev != classNumber && cur == classNumber) {
		return bonusCamel123
	}
	switch cur {
	case classNonWord, classDelimiter:
		return bonusNonWord
	case classWhite:
		return bonusBoundaryWhite
	}
	return 0
}

// Match reports whether pattern is a (case-insensitive) subsequence of text and,
// if so, the fzf score and the matched rune positions (indices into text's rune
// slice). An empty pattern matches everything with score 0 and no positions.
// Higher scores are better.
func Match(pattern, text string) (score int, positions []int, ok bool) {
	pr := []rune(pattern)
	if len(pr) == 0 {
		return 0, nil, true
	}
	tr := []rune(text)
	plo := toLower(pr)
	tlo := toLower(tr)

	// Forward pass: greedily match every pattern rune to find the end index.
	pidx, eidx := 0, -1
	for i := 0; i < len(tlo); i++ {
		if tlo[i] == plo[pidx] {
			pidx++
			if pidx == len(plo) {
				eidx = i + 1
				break
			}
		}
	}
	if eidx < 0 {
		return 0, nil, false
	}

	// Backward pass: from eidx, find the smallest start index that still matches,
	// so the scored window is as tight as possible.
	pidx = len(plo) - 1
	sidx := 0
	for i := eidx - 1; i >= 0; i-- {
		if tlo[i] == plo[pidx] {
			pidx--
			if pidx < 0 {
				sidx = i
				break
			}
		}
	}

	score, positions = calculateScore(plo, tlo, tr, sidx, eidx)
	return score, positions, true
}

func calculateScore(plo, tlo []rune, tr []rune, sidx, eidx int) (int, []int) {
	pidx := 0
	score := 0
	inGap := false
	consecutive := 0
	firstBonus := 0
	positions := make([]int, 0, len(plo))

	prevClass := classWhite
	if sidx > 0 {
		prevClass = classOf(tr[sidx-1])
	}

	for idx := sidx; idx < eidx; idx++ {
		cur := tlo[idx]
		class := classOf(tr[idx])
		if pidx < len(plo) && cur == plo[pidx] {
			positions = append(positions, idx)
			score += scoreMatch
			bonus := bonusFor(prevClass, class)
			if consecutive == 0 {
				firstBonus = bonus
			} else {
				if bonus >= bonusBoundary && bonus > firstBonus {
					firstBonus = bonus
				}
				bonus = max3(bonus, firstBonus, bonusConsecutive)
			}
			if pidx == 0 {
				score += bonus * bonusFirstCharMultiplier
			} else {
				score += bonus
			}
			inGap = false
			consecutive++
			pidx++
		} else {
			if inGap {
				score += scoreGapExtension
			} else {
				score += scoreGapStart
			}
			inGap = true
			consecutive = 0
			firstBonus = 0
		}
		prevClass = class
	}
	return score, positions
}

// Result is one ranked Filter hit.
type Result[T any] struct {
	Item      T
	Score     int
	Positions []int
}

// Filter returns the items whose key contains pattern as a fuzzy subsequence,
// sorted best-first (higher score first; ties broken by the original order for
// stability). An empty pattern returns every item, score 0, original order.
//
//	hits := fuzzy.Filter(query, users, func(u User) string { return u.Name })
func Filter[T any](pattern string, items []T, key func(T) string) []Result[T] {
	out := make([]Result[T], 0, len(items))
	if pattern == "" {
		for _, it := range items {
			out = append(out, Result[T]{Item: it})
		}
		return out
	}
	type scored struct {
		Result[T]
		ord int
	}
	tmp := make([]scored, 0, len(items))
	for i, it := range items {
		if s, pos, ok := Match(pattern, key(it)); ok {
			tmp = append(tmp, scored{Result[T]{Item: it, Score: s, Positions: pos}, i})
		}
	}
	sort.SliceStable(tmp, func(a, b int) bool {
		if tmp[a].Score != tmp[b].Score {
			return tmp[a].Score > tmp[b].Score
		}
		return tmp[a].ord < tmp[b].ord
	})
	for _, s := range tmp {
		out = append(out, s.Result)
	}
	return out
}

func toLower(rs []rune) []rune {
	out := make([]rune, len(rs))
	for i, r := range rs {
		out[i] = unicode.ToLower(r)
	}
	return out
}

func max3(a, b, c int) int {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}
