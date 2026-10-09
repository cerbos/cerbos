# Reporting security issues

Responsible disclosure of security issues is welcome through the GitHub private vulnerability reporting feature. Before reporting issues, ensure that the following criteria is met.

- Support policy is n-1. Issues that don't affect the currently released version and the version prior to it are not accepted.
- The expected deployment model of the Cerbos PDP is within a secure, internal network. It should not be directly exposed to the internet and policies should not be accepted from untrusted sources. The communication link between the application and the PDP is expected to be trusted. Any data sent to the PDP by the application is expected to be validated. Policy changes made by users are expected to be tested before going live. If an external, untrusted attacker would be able to bypass all of the above layers by exploiting a weakness in the PDP, it's a valid security vulnerability. Anything else is just a bug.
- Reports must be concise and clear. While it's acceptable to use AI tools in the discovery process, the verification and the final report should be submitted by a human. Reports containing excessively verbose LLM slop will be ignored.
