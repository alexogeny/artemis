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

The CI pipeline builds the site with `mkdocs build --strict`, uploads the `site/` folder as an artifact,
and publishes it using the official `actions/deploy-pages` workflow. The repository's GitHub Pages settings
should point at the workflow source (the `GitHub Pages` environment) rather than the legacy `gh-pages` branch.

### Troubleshooting

If the workflow finishes successfully but the site does not update, double-check the repository settings under
**Settings → Pages**. When the source is still configured to `gh-pages` (or another branch), GitHub ignores the
artifact published by `actions/deploy-pages`. Switch the source to **GitHub Actions**, or explicitly select the
`GitHub Pages` environment created by the workflow, and the next pipeline run will publish the built site.

To trigger a manual deploy outside CI you can still use MkDocs' helper. The command below builds the
site locally and pushes a `gh-pages` branch:

```shell
uv run mkdocs gh-deploy --force
```

When deploying manually, confirm that repository settings allow publishing from the `gh-pages` branch or
switch back to workflow-driven deploys by re-enabling the GitHub Pages environment.
