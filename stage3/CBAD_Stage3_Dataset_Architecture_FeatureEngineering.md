# CBAD Stage 3 — CVE Prediction Platform

## SECTION 1 — Dataset Architecture & Feature Engineering

### 1.1 Overview

Stage 3 is a commercial-grade predictive CVE risk platform built on a multi-source dataset architecture. The system ingests vulnerability feeds, source repository telemetry, issue tracker events, and package release metadata to generate a high-dimensional feature space for supervised and semi-supervised CVE prediction.

The design must support:
- ingestion from structured security feeds (NVD, GitHub Advisories, OSV, ExploitDB, Snyk)
- linkage of vulnerabilities to repository artifacts and source metadata
- feature extraction across commit velocity, issue velocity, maintainer activity, patch latency, release frequency, contributor churn, and repository age
- robust feature lineage, drift detection, and retraining pipelines

### 1.2 Ingestion Architecture

#### 1.2.1 Source feeds

1. NVD (National Vulnerability Database)
  - CVE metadata, CWE, CVSS v3 vector, affected products, published/modified dates, configurations
  - ingest via JSON feeds or API snapshot delivery

2. GitHub Advisories
  - advisory text, affected package ecosystems, CVE mappings, dependency manifests, severity ratings, patched versions
  - ingest via GitHub GraphQL API and periodic bulk export

3. OSV (Open Source Vulnerabilities)
  - normalized vulnerability records across ecosystems with affected ranges, aliases, ecosystem-specific metadata
  - ingest nightly JSON dumps or API queries

4. ExploitDB
  - exploit references, author, published date, target product, exploit type
  - ingest via CSV or API, map to CVE where available

5. Snyk
  - curated vulnerability data, remediation advice, package-level risk metadata, exploit maturity
  - ingest via Snyk API exports and private partner feeds

#### 1.2.2 Repository and artifact telemetry

- GitHub/GitLab repository metadata: stars, forks, watchers, issues, pull requests, open source status, topics, project description
- commit history and release tags via repository API or cloned repo wire
- dependency manifests and package metadata from package feeds
- package manager adoption and dependency graphs (e.g. npm, PyPI, Maven, NuGet)

#### 1.2.3 Issue and PR data

- issue creation, closing, labels, assignees, severity tags
- pull request creation, review comments, approvals, merge times, CI status
- security-related label extraction (e.g. `security`, `vulnerability`, `bug`, `high priority`)

#### 1.2.4 Exploit and threat feed linkage

- map ExploitDB and exploit maturity signals to CVEs and affected packages
- include threat actor tags, exploit availability, and exploit complexity classifications
- maintain a lookup graph linking vulnerability records to exploit references and public advisories

#### 1.2.5 Data quality and lineage

- normalize all source records to a common vulnerability schema with canonical CVE identifiers
- store raw feed snapshots and transform metadata for auditability
- maintain source provenance metadata per record: `source_name`, `ingest_timestamp`, `source_record_id`, `source_version`
- deduplicate records by alias matching across NVD, OSV, GitHub, Snyk, and ExploitDB
- track record reconciliation decisions and lineage in a metadata catalog

### 1.3 Feature engineering strategy

Feature engineering is the core of the CVE prediction model. Features are grouped into seven correlated domains that capture repository lifecycle dynamics, ecosystem behavior, and developer health.

#### 1.3.1 Principles

- use both raw counts and normalized rates to capture scale vs intensity
- compute rolling windows: 30d, 90d, 180d, 365d
- derive lagged features for temporal trend modeling
- include ratio and percentile features to normalize for repository size
- represent event velocity as both absolute frequencies and time-decayed scores
- include categorical embeddings for ecosystem, licence, and maintainer organization
- design features for explainability and operational relevance

### 1.4 Feature domains and breakdown

#### 1.4.1 Commit Velocity Features

Commit velocity is a strong proxy for development activity and risk surface expansion.

1. `commit_count_7d`
2. `commit_count_30d`
3. `commit_count_90d`
4. `commit_count_180d`
5. `commit_count_365d`
6. `commit_weekly_rate` = commit_count_30d / 4
7. `commit_daily_rate` = commit_count_30d / 30
8. `commit_velocity_trend_90d` = slope of daily commit counts over 90d
9. `commit_velocity_acceleration_90d` = change in weekly rate vs prior 90d window
10. `night_commit_ratio_90d`
11. `weekend_commit_ratio_90d`
12. `late_hour_commit_ratio_90d`
13. `commit_burst_count_30d` = number of days with > mean + 2*std dev commits
14. `avg_commit_size_30d` = average lines changed per commit
15. `median_commit_size_30d`
16. `large_commit_ratio_30d` = commits with > 500 LOC changes
17. `tiny_commit_ratio_30d` = commits with < 5 LOC changes
18. `commit_message_sentiment_avg_90d`
19. `commit_message_security_keyword_ratio_90d`
20. `commit_merge_ratio_90d` = merged commits / total commits
21. `commit_experimental_branch_ratio`
22. `commit_revert_count_90d`
23. `commit_churn_ratio_90d` = lines_added / lines_deleted
24. `commit_author_entropy_90d`
25. `commit_timezone_variance_90d`
26. `normalized_commit_latency` = avg time from branch creation to first commit
27. `commit_to_release_lag_median`
28. `commit_pattern_change_score` = rate of change in file type mix within commits
29. `commit_dependency_change_ratio` = ratio of commits touching dependency manifests
30. `commit_security_label_ratio_90d`

#### 1.4.2 Issue Velocity Features

Issue velocity measures bug discovery and remediation load.

31. `issue_count_open_30d`
32. `issue_count_closed_30d`
33. `issue_count_created_90d`
34. `issue_count_closed_90d`
35. `issue_close_rate_90d` = closed / created
36. `issue_backlog_age_median`
37. `issue_severity_high_count_90d`
38. `issue_severity_medium_count_90d`
39. `issue_security_label_count_90d`
40. `issue_bug_label_ratio_90d`
41. `issue_vulnerability_label_ratio_90d`
42. `issue_triage_latency_median`
43. `issue_resolution_latency_median`
44. `issue_reopen_ratio_90d`
45. `issue_comment_rate_90d`
46. `issue_participant_entropy_90d`
47. `issue_critical_path_ratio`
48. `issue_sla_breach_rate_90d`
49. `issue_assignee_churn_90d`
50. `issue_label_change_velocity`
51. `issue_dependency_report_ratio`
52. `issue_cve_link_ratio`
53. `issue_public_disclosure_ratio`
54. `issue_external_report_ratio`
55. `issue_security_banner_count`
56. `issue_topic_mismatch_score`
57. `issue_severity_escalation_rate`
58. `issue_p1_count_90d`
59. `issue_patch_request_ratio`
60. `issue_comment_sentiment_avg_90d`
61. `issue_sla_compliance_ratio`
62. `issue_triage_response_time_90d`
63. `issue_vulnerability_triage_completion_rate`
64. `issue_automated_detection_ratio`
65. `issue_one_touch_fix_ratio`
66. `issue_security_review_count_90d`
67. `issue_owner_assignment_stability`
68. `issue_skip_label_ratio` = issues without labels before closing
69. `issue_public_notification_count`
70. `issue_identified_by_external_audit_ratio`

#### 1.4.3 Maintainer Activity Features

Maintainer activity captures trust, review throughput, and account health.

71. `maintainer_count_active_90d`
72. `maintainer_count_total`
73. `maintainer_churn_90d` = new maintainers - departed maintainers
74. `maintainer_bus_factor`
75. `maintainer_commit_share_top3`
76. `maintainer_review_share_top3`
77. `maintainer_last_active_days`
78. `maintainer_response_time_median`
79. `maintainer_organization_diversity`
80. `maintainer_verified_key_ratio`
81. `maintainer_public_key_age_median`
82. `maintainer_security_policy_published`
83. `maintainer_2fa_enforced_ratio`
84. `maintainer_suspicious_account_ratio`
85. `maintainer_issue_comment_rate`
86. `maintainer_pr_review_rate`
87. `maintainer_pull_request_latency_median`
88. `maintainer_package_release_readiness_score`
89. `maintainer_trust_score_avg`
90. `maintainer_role_entropy`
91. `maintainer_transport_layer_diversity` (SSH vs HTTPS commits)
92. `maintainer_ci_access_change_rate`
93. `maintainer_auth_method_change_rate`
94. `maintainer_code_ownership_change_ratio`
95. `maintainer_contributor_onboarding_time`
96. `maintainer_security_issue_response_time_90d`
97. `maintainer_repo_access_growth_rate`
98. `maintainer_code_review_participation_ratio`
99. `maintainer_name_discrepancy_score`
100. `maintainer_source_ip_variance_90d`

#### 1.4.4 Patch Latency Features

Patch latency is a critical leading indicator for CVE exposure.

101. `patch_latency_median_90d` = median days from vulnerability disclosure to patch merge
102. `patch_latency_90th_percentile`
103. `patch_latency_99th_percentile`
104. `patch_latency_mean_90d`
105. `patch_latency_due_to_dependency_review`
106. `patch_latency_for_security_labels`
107. `patch_latency_for_high_severity_prs`
108. `patch_latency_for_patch_releases`
109. `patch_latency_external_contrib_ratio`
110. `patch_latency_from_issue_open`
111. `patch_latency_from_pr_open`
112. `patch_latency_from_cve_publish`
113. `patch_latency_missing_tests_ratio`
114. `patch_latency_due_to_build_failures`
115. `patch_lag_release_gap`
116. `patch_latency_sprint_boundaries_ratio`
117. `patch_latency_by_maintainer_experience`
118. `patch_latency_with_security_review`
119. `patch_backport_latency`
120. `patch_latency_after_exploit_publication`

#### 1.4.5 Release Frequency Features

Release cadence and stability affect exploit window and fix propagation.

121. `release_count_30d`
122. `release_count_90d`
123. `release_count_180d`
124. `release_count_365d`
125. `release_interval_median_90d`
126. `release_interval_stddev_90d`
127. `release_velocity_trend_180d`
128. `release_major_count_90d`
129. `release_minor_count_90d`
130. `release_patch_count_90d`
131. `release_prerelease_ratio`
132. `release_backport_count_90d`
133. `release_hotfix_ratio`
134. `release_rollout_stability_score`
135. `release_revert_ratio_90d`
136. `release_churn_ratio_90d`
137. `release_dependency_update_ratio`
138. `release_security_update_ratio`
139. `release_cve_remediation_rate`
140. `release_documentation_update_ratio`
141. `release_tag_consistency_score`
142. `release_signing_ratio`
143. `release_downstream_consumption_ratio`
144. `release_staleness_ratio` = releases older than 180d divided by total releases
145. `release_feature_branch_ratio`
146. `release_regression_rate`
147. `release_security_bump_ratio`
148. `release_tag_gap_count_90d`
149. `release_time_to_next_patch_median`
150. `release_dependency_hardening_score`

#### 1.4.6 Contributor Churn Features

Contributor churn measures community stability and risk of knowledge loss.

151. `contributor_count_90d`
152. `new_contributor_count_90d`
153. `departed_contributor_count_90d`
154. `contributor_turnover_rate_90d`
155. `contributor_retention_rate_180d`
156. `contributor_growth_rate_180d`
157. `contributor_commit_frequency_90d`
158. `contributor_review_frequency_90d`
159. `contributor_experience_median`
160. `contributor_onboarding_latency_median`
161. `contributor_pr_approval_rate`
162. `contributor_issue_resolution_rate`
163. `contributor_dependency_change_share`
164. `contributor_ownership_change_rate`
165. `contributor_security_label_engagement`
166. `contributor_maintainer_transition_rate`
167. `contributor_suspicious_account_ratio`
168. `contributor_repo_cloning_rate`
169. `contributor_access_request_rate`
170. `contributor_override_action_ratio`
171. `contributor_unreviewed_commit_ratio`
172. `contributor_release_participation_rate`
173. `contributor_public_profile_completeness`
174. `contributor_code_review_depth`
175. `contributor_code_quality_issue_rate`
176. `contributor_documentation_commit_rate`
177. `contributor_ci_failure_share`
178. `contributor_security_pr_count`
179. `contributor_bugfix_vs_feature_ratio`
180. `contributor_community_interaction_score`

#### 1.4.7 Repository Age and Maturity Features

Repository age captures institutional knowledge, legacy exposure, and maintenance health.

181. `repo_age_days`
182. `repo_age_years`
183. `repo_age_bucket` = young / mature / legacy
184. `time_since_first_release`
185. `time_since_last_release`
186. `time_since_last_commit`
187. `time_since_last_security_fix`
188. `time_since_last_dependency_update`
189. `time_since_last_maintainer_activity`
190. `repo_activity_decay_rate`
191. `repo_age_vs_activity_ratio`
192. `repository_maturity_score`
193. `legacy_code_ratio` = files older than 2 years / total files
194. `outdated_dependency_ratio`
195. `deprecated_api_usage_ratio`
196. `repository_social_age` = public repo presence duration
197. `repo_fork_age_distribution`
198. `repo_age_cohort_risk_factor`
199. `repo_license_maturity_score`
200. `repo_archival_risk_score`
201. `repo_docs_age_ratio`
202. `repo_security_policy_age`
203. `repo_ownership_stability_score`
204. `repo_release_maturity_balance`
205. `repo_onboarding_friction_index`

### 1.5 Statistical considerations

- features will be stored as dense numeric vectors plus categorical embeddings for ecosystem, license, and repository type
- apply `z-score` normalization per feature based on training distribution
- use quantile capping for heavy-tailed features such as commit size and issue counts
- compute feature importance with SHAP or permutation importance during model validation
- monitor feature drift with KL divergence and population statistics for each window
- maintain a catalog of feature definitions and transformations for reproducibility

### 1.6 Operational pipeline

1. ingest raw feeds nightly and append to raw source store
2. canonicalize and normalize vulnerability records
3. join vulnerability data with repository and package records
4. compute time-windowed features from repo telemetry and issue/commit events
5. label training targets using historical CVE assignments and affected package mappings
6. validate feature quality, handle missing values, and persist feature vectors to model training store
7. deliver feature metadata and lineage to MLOps feature registry

### 1.7 Feature lineage and governance

- assign stable feature IDs and semantic descriptions
- version feature generation code in Git and track via schema registry
- implement feature validation tests for completeness, null rates, and range bounds
- record source contribution for each feature: `source_feed`, `repo_event`, `issue_event`, `release_event`
- support feature backfill with reproducible historical computation

### 1.8 Example feature groups by source

- NVD/OSV/Snyk: `cve_age`, `affected_package_count`, `exploit_available`, `patch_provided`, `cvss_trend`
- GitHub Advisories: `advisory_issue_relation`, `security_label_response_time`, `advisory_release_alignment`
- ExploitDB: `exploit_publication_lag`, `exploit_maturity_score`
- repository telemetry: `commit_velocity`, `release_frequency`, `maintainer_activity`
- issue data: `bug_velocity`, `security_triage_latency`, `issue_reopen_rate`

### 1.9 Summary

This dataset architecture and feature engineering design provides a high-resolution foundation for a CVE prediction platform. It combines multi-source vulnerability data with rich repository behavioral signals, using 205+ features across velocity, activity, latency, frequency, churn, and maturity domains.
