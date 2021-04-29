# Prisma Cloud Scan Action
This GitHub Action will scan container images for vulnerabilities and compliance issues using Prisma Cloud by Palo Alto Networks. Receive immediate feedback about image vulnerabilities and compliance violations both in GitHub and in the Prisma Cloud Console. Block merges that do not meet your compliance requirements, such as updates with critical vulnerabilities.

This action is a wrapper around [twistcli](https://docs.twistlock.com/docs/compute_edition/tools/twistcli_scan_images.html) which connects to the specified Prisma Cloud Console for vulnerability and compliance policy and metadata.


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

      - name: Prisma Cloud image scan
        uses: PaloAltoNetworks/prisma-cloud-scan@v1
        with:
          pcc_console_url: ${{ secrets.PCC_CONSOLE_URL }}
          pcc_user: ${{ secrets.PCC_USER }}
          pcc_pass: ${{ secrets.PCC_PASS }}
          image_name: ${{ env.IMAGE_NAME }}
```


## Properties

### Inputs
| Input | Description | Required? | Default |
|---|---|---|---|
| `pcc_console_url` | URL of your Prisma Cloud Compute Console | Yes |  |
| `pcc_user` | Username of a user with the CI user role | Yes |  |
| `pcc_pass` | Password of a user with the CI user role | Yes |  |
| `image_name` | Name (or ID) of the image to be scanned | Yes |  |
| `results_file` | File to which scan results are written in JSON | No | `pcc_scan_results.json` |

### Output file
| Output | Description |
|---|---|
| `results_file` | File to which scan results are written in JSON |

## Control alerting and fail thresholds
You can set the level for alerting and failing builds in the Prisma Cloud UI. For example, setting the alert threshold to Medium will not alert for Low severity vulnerabilities.
<br /><br />
<img src="./images/pc_ci_rule_example.png">


## Results output
The table of discovered vulnerabilities and compliance violations shows up in the GitHub workflow log and in the Prisma Cloud Console in the Monitor section.

### GitHub workflow log
<img src="./images/pc_github_log_output.png">

### Prisma Cloud Console view
<img src="./images/pc_ui_result.png">
