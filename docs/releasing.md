# Releasing susu

GitHub releases are created automatically from semantic-version tags by [the release workflow](../.github/workflows/release.yml).

## Prepare a release

1. Update `CHANGELOG.md` for the version being released.
2. Ensure the intended commit is on the protected release branch and the working tree is clean.
3. Run the full test suite:

   ```bash
   mise exec -- go test ./...
   ```

## Publish a release

Create and push a semantic-version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Tags with a semantic-version prerelease suffix, such as `v0.2.0-rc.1`, produce GitHub prereleases. Other `v*` tags are accepted by the workflow trigger but may be rejected by GoReleaser if they are not valid release versions.

The workflow verifies modules, runs the test suite, and invokes GoReleaser. It publishes `.tar.gz` archives for:

- Linux: `amd64`, `arm64`;
- macOS / Darwin: `amd64`, `arm64`.

Each archive contains the `susu` binary, `README.md`, `LICENSE`, and `CHANGELOG.md`. The release also includes `checksums.txt` for artifact verification.

The workflow uses the repository-provided `GITHUB_TOKEN` with `contents: write`; no separate release secret is required.
