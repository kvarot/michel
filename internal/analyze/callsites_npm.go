package analyze

import "strings"

func findJS(projectRoot, manifestDir string, others []string, pkg string, exclude []string) (CallSites, error) {
	files, err := userFiles(projectRoot, manifestDir, others, exclude,
		[]string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", ".vue", ".svelte"})
	if err != nil {
		return CallSites{}, err
	}
	var needles []string
	for _, q := range []string{"'", `"`} {
		needles = append(needles,
			"require("+q+pkg+q+")",
			"from "+q+pkg+q,
			"import("+q+pkg+q+")",
			"import "+q+pkg+q,
			q+pkg+"/",
		)
	}
	res, err := scanFiles(projectRoot, files, func(line string) bool {
		for _, n := range needles {
			if strings.Contains(line, n) {
				return true
			}
		}
		return false
	})
	res.Quality = "import"
	return res, err
}
