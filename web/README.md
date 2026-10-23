`npm ci` installs the exact versions of `package-lock.json`.
`npm run dev` serves the page on http://localhost:5173 and sends `/api` to a running `michel serve` (127.0.0.1:7331); open it with `?token=` from the link `michel serve` prints.
`npm run build` writes `dist/`, which `go build` embeds in the binary (or run `make web` from the repository root).
