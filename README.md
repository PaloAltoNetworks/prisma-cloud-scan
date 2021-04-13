# Prisma Cloud Scan Action
Scan container images for vulnerabilities and compliance issues using this GitHub action.
This action is a wrapper around [twistcli](https://docs.twistlock.com/docs/compute_edition/tools/twistcli_scan_images.html) which connects to the specified Prisma Cloud Compute Console for vulnerability and compliance policy and metadata.

## Usage
### Example of container image scanning
```yaml
on: [ push, workflow_dispatch ]

env:
  IMAGE_NAME: ${{ github.repository }}:${{ github.sha }}

jobs:
  build-and-scan:
    name: Build and scan image
    runs-on: ubuntu-latest

    steps:
      - name: Check out the repository
        uses: actions/checkout@v2

      - name: Build the image
        run: docker build -t $IMAGE_NAME .

      - name: Prisma Cloud Compute scan
        uses: PaloAltoNetworks/prisma-cloud-scan@v1
        with:
          pcc_console_url: ${{ secrets.PCC_CONSOLE_URL }}
          pcc_user: ${{ secrets.PCC_USER }}
          pcc_pass: ${{ secrets.PCC_PASS }}
          image_name: ${{ env.IMAGE_NAME }}
```

## Inputs
| Input | Description | Required? | Default |
|---|---|---|---|
| `pcc_console_url` | URL of your Prisma Cloud Compute Console | Yes |  |
| `pcc_user` | Username of a user with the CI user role | Yes |  |
| `pcc_pass` | Password of a user with the CI user role | Yes |  |
| `image_name` | Name (or ID) of the image to be scanned | Yes |  |
| `results_file` | File to which scan results are written in JSON | No | `pcc_scan_results.json` |

## Outputs
| Output | Description |
|---|---|
| `results_file` | File to which scan results are written in JSON |
