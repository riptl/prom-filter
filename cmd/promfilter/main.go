package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

func main() {
	listen := flag.String("listen", "", "Listen address (required)")
	prom := flag.String("prom", "", "Prometheus URL (required)")
	whitelistPath := flag.String("whitelist", "", "Path to whitelist file (required)")
	flag.Parse()
	if flag.NArg() > 0 || *listen == "" || *prom == "" || *whitelistPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Read in whitelist.
	allowedQueries := readWhitelist(*whitelistPath)

	// Create reverse proxy module.
	promURL, err := url.Parse(*prom)
	if err != nil {
		panic("invalid prom URL: " + err.Error())
	}
	proxy := httputil.NewSingleHostReverseProxy(promURL)

	http.Handle("/", http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/query":
			var query string
			if req.Method == http.MethodGet {
				query = req.URL.Query().Get("query")
			} else if req.Method == http.MethodPost {
				query = req.FormValue("query")
			}
			expr, err := parser.ParseExpr(query)
			if err != nil {
				http.Error(wr, err.Error(), http.StatusBadRequest)
				return
			}
			var ok bool
			for _, allowed := range allowedQueries {
				m := queryMatcher{
					tpl: allowed,
				}
				if m.equalExpressions(allowed.expr, expr) {
					ok = true
					break
				}
			}
			if !ok {
				http.Error(wr, "fuck you", http.StatusForbidden)
				return
			}
		}
		// Let through the original request.
		proxy.ServeHTTP(wr, req)
	}))
	http.ListenAndServe(*listen, nil)
}

type queryTemplate struct {
	Query string                 `json:"query"`
	Vars  map[string]*queryParam `json:"vars"`

	expr         parser.Expr
	finalQuery   string
	placeholders map[string]*queryParam
}

func (q *queryTemplate) prepare() {
	replacements := make([]string, 2*len(q.Vars))
	q.placeholders = make(map[string]*queryParam)
	i := 0
	for k, v := range q.Vars {
		placeholder := genPlaceholder()
		replacements[i] = "$" + k
		replacements[i+1] = placeholder
		q.placeholders[placeholder] = v
		i += 2
	}
	q.finalQuery = strings.NewReplacer(replacements...).Replace(q.Query)
	var err error
	q.expr, err = parser.ParseExpr(q.finalQuery)
	if err != nil {
		panic("invalid query: " + err.Error())
	}
}

type queryParam struct {
	Any []string `json:"any"`
}

func genPlaceholder() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err.Error())
	}
	return hex.EncodeToString(buf[:])
}

func readWhitelist(path string) (out []*queryTemplate) {
	buf, err := os.ReadFile(path)
	if err != nil {
		panic("failed to read whitelist: " + err.Error())
	}
	if err := json.Unmarshal(buf, &out); err != nil {
		panic("failed to read whitelist: " + err.Error())
	}
	for _, tpl := range out {
		tpl.prepare()
	}
	return
}

type queryMatcher struct {
	tpl *queryTemplate
}

func (m *queryMatcher) equalExpressions(left, right parser.Expr) bool {
	switch leftVal := left.(type) {
	case *parser.BinaryExpr:
		rightVal, ok := right.(*parser.BinaryExpr)
		if !ok {
			return false
		}
		if leftVal.Op != rightVal.Op {
			return false
		}
		if !m.equalExpressions(leftVal.LHS, rightVal.LHS) {
			return false
		}
		if !m.equalExpressions(leftVal.RHS, rightVal.RHS) {
			return false
		}
		// TODO VectorMatching
		// TODO ReturnBool
		return true
	case *parser.AggregateExpr:
		rightVal, ok := right.(*parser.AggregateExpr)
		if !ok {
			return false
		}
		if leftVal.Op != rightVal.Op {
			return false
		}
		if !m.equalExpressions(leftVal.Expr, rightVal.Expr) {
			return false
		}
		if !m.equalExpressions(leftVal.Param, rightVal.Param) {
			return false
		}
		if !equalStrings(leftVal.Grouping, rightVal.Grouping) {
			return false
		}
		if leftVal.Without != rightVal.Without {
			return false
		}
		return true
	case *parser.Call:
		rightVal, ok := right.(*parser.Call)
		if !ok {
			return false
		}
		if leftVal.Func != rightVal.Func {
			return false
		}
		if len(leftVal.Args) != len(rightVal.Args) {
			return false
		}
		for i := range leftVal.Args {
			if !m.equalExpressions(leftVal.Args[i], rightVal.Args[i]) {
				return false
			}
		}
		return true
	case *parser.MatrixSelector:
		rightVal, ok := right.(*parser.MatrixSelector)
		if !ok {
			return false
		}
		if !m.equalExpressions(leftVal.VectorSelector, rightVal.VectorSelector) {
			return false
		}
		if leftVal.Range != rightVal.Range {
			return false
		}
		return true
	case *parser.VectorSelector:
		rightVal, ok := right.(*parser.VectorSelector)
		if !ok {
			return false
		}
		if leftVal.Name != rightVal.Name {
			return false
		}
		if leftVal.OriginalOffset != rightVal.OriginalOffset {
			return false
		}
		if leftVal.Offset != rightVal.Offset {
			return false
		}
		if (leftVal.Timestamp == nil) != (rightVal.Timestamp == nil) {
			return false
		}
		if leftVal.Timestamp != nil && *leftVal.Timestamp != *rightVal.Timestamp {
			return false
		}
		if leftVal.StartOrEnd != rightVal.StartOrEnd {
			return false
		}
		if len(leftVal.LabelMatchers) != len(rightVal.LabelMatchers) {
			return false
		}
		for i := range leftVal.LabelMatchers {
			if !m.equalMatcher(leftVal.LabelMatchers[i], rightVal.LabelMatchers[i]) {
				return false
			}
		}
		return true
	case *parser.NumberLiteral:
		// TODO Special values check
		rightVal, ok := right.(*parser.NumberLiteral)
		if !ok {
			return false
		}
		if leftVal.Val != rightVal.Val {
			return false
		}
		return true
	default:
		panic(fmt.Sprintf("unsupported expr %T", left))
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (m *queryMatcher) equalMatcher(left, right *labels.Matcher) bool {
	if left.Type != right.Type {
		return false
	}
	if left.Name != right.Name {
		return false
	}
	queryVar, ok := m.tpl.placeholders[left.Value]
	if ok {
		var match bool
		for _, v := range queryVar.Any {
			if v == right.Value {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	} else if left.Value != right.Value {
		return false
	}
	return true
}
