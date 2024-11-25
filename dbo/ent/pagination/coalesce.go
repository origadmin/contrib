// Package pagination implements the functions, types, and interfaces for the module.
package pagination

import (
	"entgo.io/ent/dialect/sql"
)

// CoalesceMax returns the max value of the given field.
func CoalesceMax(field string) func(selector *sql.Selector) string {
	return func(selector *sql.Selector) string {
		fn := sql.Func{}
		fn.Append(func(builder *sql.Builder) {
			builder.WriteString("COALESCE")
			builder.Wrap(func(b *sql.Builder) {
				b.Ident(sql.Max(selector.C(field))).Comma().WriteByte('0')
			})
		})
		return fn.String()
	}
}
