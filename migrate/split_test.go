package migrate

import "testing"

func TestSplitSQL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"two simple statements", "CREATE TABLE a (id int); CREATE TABLE b (id int);", 2},
		{"trailing no semicolon", "SELECT 1", 1},
		{"semicolon inside single quotes", "INSERT INTO t VALUES ('a;b'); SELECT 1;", 2},
		{"line comment with semicolon", "SELECT 1; -- a; b\nSELECT 2;", 2},
		{"block comment with semicolon", "SELECT 1; /* a; b; c */ SELECT 2;", 2},
		{
			"dollar-quoted plpgsql body is one statement",
			"CREATE FUNCTION f() RETURNS int AS $$ BEGIN x := 1; y := 2; RETURN x; END; $$ LANGUAGE plpgsql; SELECT 1;",
			2,
		},
		{
			"tagged dollar quote",
			"CREATE FUNCTION g() RETURNS int AS $body$ BEGIN RETURN 1; END; $body$ LANGUAGE plpgsql;",
			1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SplitSQL(c.in)
			if len(got) != c.want {
				t.Fatalf("SplitSQL(%q) returned %d statements %#v, want %d", c.in, len(got), got, c.want)
			}
		})
	}
}
