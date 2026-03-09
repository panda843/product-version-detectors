package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"

	version "github.com/panda843/product-version-detectors"
)

func main() {
	v := version.New()
	productStr, vendor, target := "", "", ""
	flag.StringVar(&productStr, "product", "", "product name")
	flag.StringVar(&vendor, "vendor", "", "vendor name")
	flag.StringVar(&target, "target", "", "target address")
	flag.Parse()
	if target == "" {
		fmt.Println("Please specify target address")
		os.Exit(1)
	}
	if productStr == "" {
		var wg sync.WaitGroup
		for _, pName := range v.Products() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				vers, err := v.Check(context.Background(), pName, pName, vendor, target)
				if err != nil {
					fmt.Println("product:", pName, "\t", "target:", target, "\t", "version:", "failed")
				} else {
					if vers == "" {
						vers = "failed"
					}
					fmt.Println("product:", pName, "\t", "target:", target, "\t", "version:", vers)
				}
			}()
		}
		wg.Wait()
	} else {
		vers, err := v.Check(context.Background(), productStr, productStr, vendor, target)
		if err != nil {
			fmt.Println("product:", productStr, "\t", "target:", target, "\t", "version:", "failed")
		} else {
			if vers == "" {
				vers = "failed"
			}
			fmt.Println("product:", productStr, "\t", "target:", target, "\t", "version:", vers)
		}
	}
}
