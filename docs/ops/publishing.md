# Publishing documentation

Mere's documentation is built with MkDocs using the shadcn theme. The site can be deployed to GitHub
Pages directly from the repository.

## Prerequisites

Ensure development dependencies are installed:

```shell
uv sync
```

## Build locally

Generate a production build to validate styling and links:

```shell
uv run mkdocs build --strict
```

The output lives in `site/` and matches what GitHub Pages will host.

## Deploy to GitHub Pages

Use the MkDocs deployment helper:

```shell
uv run mkdocs gh-deploy --force
```

The command builds the site and pushes it to the `gh-pages` branch. Configure the repository's GitHub
Pages settings to serve content from that branch. Subsequent deployments reuse the same command.
