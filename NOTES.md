Day 1 of getting started 
So I will be starting the assignment from scratch
Setting up my project folder and basic structure
For python, I am depending on the documentation
My goal is to understand data before writing any models
I loaded beacon_events_train.csv successfully
The dataset has 10000 rows and 15 columns
I observed multiple protocols that includes DNS, TCP and HTTPS
proc_name includes both common applications and suspicious exe files 



Day 2 - Missing Value Analysis
I founded missing values only in inter_event_seconds (500 rows)
Missing values likely correspond to first-seen connections where there are no prior connections existing to compute a time difference.
inter_event_seconds is important for detecting periodic beaconing
Missing values are not random and must be handled explicitly during preprocessing


Day 2 continuation : Label Distribution
Dataset contains 7,764 benign events (77.64%) and 2,236 malicious events (22.36%)
Malicious activity is less frequent than benign activity
Class imbalance means accuracy alone is not sufficient; recall and precision will be important

Day 2 – Inter-Event Timing Analysis
- inter_event_seconds is heavily right-skewed overall
- Benign events show irregular timing
- Malicious events show tight clustering around ~60-second intervals

Day 2 – Traffic Volume Analysis
- Explored bytes_out and bytes_in distributions
- Benign traffic shows high variability and large transfers
- Malicious traffic is constrained to smaller, more consistent sizes
- bytes_out vs bytes_in shows chaotic patterns for benign traffic and compact patterns for malicious traffic
- Traffic volume supports beacon detection but is not sufficient alone

Day 2 – Destination Ports & Protocols
- Both benign and malicious traffic predominantly use common ports such as 80, 443, 53 and 8080
- Malicious traffic does not rely on rare or unusual ports
- Protocol usage heavily overlaps between benign and malicious events
- Port and protocol are weak signals alone but useful when combined with behavioral features

Day 2 – Process Context Analysis
- Benign traffic is dominated by common user-facing applications
- Malicious events are concentrated in a smaller set of processes
- Scripting engines and LOLBins appear disproportionately in malicious events
- Process name alone is not definitive and must be combined with behavioral features

Day 2 – GeoIP / Country Code Analysis
- Benign traffic is distributed across common enterprise and SaaS regions
- Malicious traffic shows a different distribution with more concentration in fewer countries
- US appears in both benign and malicious events, indicating GeoIP is not definitive
- Country information provides weak contextual signal and must be combined with other features
- GeoIP-based detection is limited by VPNs, CDNs and cloud hosting

End of EDA Phase
- Completed exploratory analysis across timing, volume, ports, processes and GeoIP
- Identified multiple behavioral signals consistent with C2 beaconing
- Next step is to formalize these insights into derived features for modeling

Feature 1 – Timing Beacon-ness 
- Attempted to compute timing variance per connection, but dataset contained only single events per (host_id, dst_ip)
- This indicates event-level data without repeated temporal sequences
- Feature was redefined to use per-event timing characteristics instead
- Timing remains a strong signal due to clustering around common beacon intervals

Feature 1 – Timing Beacon-ness (Final)
- Dataset is event-level. Repeated timing sequences per connection are not available
- Implemented per-event timing beacon-ness using absolute distance from 60-second interval
- Malicious events cluster tightly near 60s, benign events are widely distributed
- Smaller distance indicates more beacon-like behavior
- Legitimate scheduled tasks may also produce regular intervals

Feature 2 – Port Weirdness
- Identified top 10 most common destination ports
- Created binary feature indicating rare vs common ports
- Malicious events use rare ports slightly more often
- Port number alone is a weak signal and must be combined with other features

Feature 3 – Process Risk Score
- Assigned coarse risk levels to processes based on abuse potential
- LOLBins and known offensive tools assigned higher risk
- Common user-facing applications assigned lower risk
- Malicious events show significantly higher average process risk
- Process name alone is insufficient and requires behavioral context

Feature 4 – GeoIP Risk Buckets
- Assigned coarse GeoIP risk buckets based on observed dataset distribution
- Malicious traffic shows higher average GeoIP risk
- Significant overlap exists between benign and malicious destinations
- GeoIP is a weak contextual signal due to VPNs, CDNs and cloud hosting

Day 3 – Detection Pipeline & Analyst Reporting
- Implemented full end-to-end detection pipeline with feature engineering, supervised classification and unsupervised anomaly detection
- Built scoring and fusion logic to produce continuous risk scores
- Applied trained models to live unlabeled data and prioritized hosts for investigation
- Documented findings and limitations in an analyst-facing security report


Day 4 – Engineering Hygiene & Packaging
- Added sanity tests for feature engineering, training pipeline and scoring logic
- Fixed Python import paths for pytest compatibility
- Containerized the project using Docker with a clean, reproducible setup
- Added GitHub Actions CI to run tests and linting on each push
- Finalized analyst-facing documentation and integrity statement

Issues & Fixes Encountered
- Feature mismatch errors when training before feature engineering was modularized
- Import errors during pytest execution due to Python path resolution
- Adjusted Docker entrypoint to support modular execution

What I would do next with more time:
- Add domain-level
- Incorporate longer historical windows for beacon detection
- Add feedback-driven retraining based on analyst decisions
- Expand test coverage for edge cases and failure modes