# Overview

Gitlab CI/CD establishes connection with FortiPenTest REST API server
and triggers automated scan upon each commit.

# 2.Integrating FortiPenTest with Gitlab for CI/CD

## 2.1. Configuration Details Needed from UI

-   Go to the FortiPenTest UI.

-   Click on User icon and click on settings.

-   Under API Key Generation, go to Privileged tab click on Generate
    Button to generate API Key.

-   Copy the API Key.

-   Similarly copy the Scan URL and its UUID from Inventory page.

## 2.2. Configuring Gitlab

-   Login to your Gitlab account.

-   Go to the project you want to work with.

-   Register gitlab runner with your project. Steps to register a
    runner: <https://docs.gitlab.com/runner/register/>.

-   Copy the file scan.py from the src directory to the project you are
    working.

-   Click on "Set up CI/CD Button". This opens a CI/CD editor to update
    or create the yml file .gitlab-ci.yml

-   Copy the contents of file .gitlab-ci.yml from the src directory to
    the CI Editor of your project and edit the variables.

-   Provide the Tag name that was used while registering the runner.

-   Paste the API Key, Scan URL, UUID that is copied from FortiPenTest
    UI.

-   Provide the FortiPenTest API URL.

-   Provide scantype (Quick Scan = 0, Full Scan = 1)

-   Commit .gitlab-ci.yml file

-   Every commit will create a job and triggers a scan to FortiPenTest
