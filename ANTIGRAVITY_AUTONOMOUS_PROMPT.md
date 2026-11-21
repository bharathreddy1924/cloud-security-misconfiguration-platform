# Antigravity autonomous project execution prompt

You are working on my capstone project:

**Cloud Security Misconfiguration Detection Platform**

Team:
- Gangana Bharath Simha Reddy — BT23GCS494
- Garre Lakhmi Narayana — BT23GCS253
- Charugundla Hemendra Venkata Lalith — BT23GCS254

## Execution preference
Work autonomously and complete the project end-to-end. Do not stop to ask me to choose between routine implementation options, file edits, commands, package installation, test runs, local builds, or normal debugging steps. Choose sensible, secure defaults and continue. If the IDE presents an approval/permission dialog, use the broadest available **workspace-scoped / project-scoped** permission that allows normal development commands and file edits, if that is permitted by my configured policy. Do not repeatedly ask for approval for the same safe workspace operation when an “always allow for this workspace” option is available.

Do not bypass operating-system security, endpoint protection, account authentication, organisation policy, or explicit destructive-action safeguards. Never expose secrets, upload credentials, delete unrelated files, deploy to paid cloud resources, publish a public image, or make external changes without a clear requirement. If a genuinely high-impact or irreversible action is blocked, stop only that action, explain it briefly, and continue all independent work.

## Project goals
1. Inspect the existing repository before changing it.
2. Preserve working code and improve it rather than replacing it unnecessarily.
3. Finish a functional web dashboard and REST API for detecting cloud security misconfigurations.
4. Implement and test transparent rules for:
   - Public S3 bucket access
   - Disabled S3 encryption
   - SSH/RDP open to the internet
   - IAM wildcard permissions
   - Publicly accessible databases
   - Disabled CloudTrail logging
   - Unencrypted EBS volumes
5. Keep the prototype safe: accept supplied JSON inventory. Do not request or store real cloud credentials. Do not claim live AWS scanning unless read-only AWS integration is actually implemented and tested.
6. Use MongoDB for scan history, with graceful operation if the database is unavailable.
7. Provide Dockerfile and Docker Compose for the app and database.
8. Provide a Jenkins pipeline that checks out code, installs dependencies, runs tests, and builds a Docker image.
9. Add meaningful automated tests, input validation, useful error handling, and clear setup documentation.
10. Ensure the UI is responsive, understandable, and suitable for a capstone demonstration.

## Work process
- Start by reading README, package files, source, tests, Docker files, and Jenkinsfile.
- Make a short implementation checklist internally and execute it without asking me to approve each item.
- Run tests after changes. Fix failures and rerun tests.
- Run lint/build checks if configured; add a lightweight check only if useful.
- Verify API health and scan endpoints where possible.
- Verify Docker Compose configuration/build where Docker is available.
- Review for hard-coded secrets, unsafe defaults, and misleading claims.
- Update README with exact commands, API examples, limitations, testing evidence, and demonstration steps.
- Keep all work inside this project folder.
- Do not fabricate successful test, Docker, Jenkins, or cloud results. Clearly label anything that could not be run in this environment.

## Assessment rubric
Total: 30 marks.
- Presentation: 15 — I will prepare this myself; do not create or spend time on the presentation.
- JIRA: 3 — I will prepare this myself; do not create or spend time on JIRA.
- Git/GitHub: 3
- Docker: 3
- Jenkins: 3
- Testing: 3

Complete and document the technical work for Git/GitHub, Docker, Jenkins, and Testing. Do not attempt to complete the presentation or JIRA marks.

## Final response required
When finished, report:
- Features implemented
- Files changed/added
- Exact commands to run the project
- Tests executed and actual results
- Docker/Jenkins verification status
- Any remaining manual steps that truly require me
- A concise capstone demo sequence

Do not ask me routine “which option?” questions. Make reasonable decisions and keep going.
