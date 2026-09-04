package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	table := flag.String("table", "", "dynamodb table name")
	prefix := flag.String("tenant-key-prefix", "", "partition key prefix that identifies a tenant, e.g. org#")
	flag.Parse()

	if *table == "" {
		fmt.Fprintln(os.Stderr, "usage: tenantaudit --table <name> [--tenant-key-prefix <prefix>]")
		os.Exit(2)
	}

	_ = prefix
	fmt.Println("not implemented yet")
}
