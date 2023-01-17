package main

import (
	"fmt"
	"github.com/gocolly/colly"
)

// scrape XKCD for the comic of the day w/alt text
func main() {
	c := colly.NewCollector(
		colly.AllowedDomains("www.xkcd.com", "xkcd.com"),
	)

	c.OnHTML("#comic > img", func(e *colly.HTMLElement) {
		fmt.Println("https:" + e.Attr("src"))
		fmt.Println(e.Attr("title"))
	})

	err := c.Visit("https://www.xkcd.com")
	if err != nil {
		fmt.Println(err)
	}
}
