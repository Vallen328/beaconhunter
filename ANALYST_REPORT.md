2.1 Executive Summary (Non-Technical)

This project addresses the challenge of identifying potential command-and-control (C2) beaconing activity within large volumes of outbound network traffic. In real enterprise environments, security teams are often faced with thousands of network events per day, many of which appear benign in isolation. The goal is not to label every event as malicious or safe, but to help analysts quickly identify which hosts and connections warrant closer investigation.

To support this goal, an analytics-driven detection system was developed to score and prioritize network events based on how closely they resemble known C2 beaconing behavior. Rather than relying on a single indicator, the system combines multiple behavioral and contextual signals to estimate risk. These signals include communication timing patterns, traffic volume characteristics, initiating process context, destination port usage, and coarse geographic information. Each event is assigned a continuous risk score between 0 and 1, where higher values indicate stronger alignment with beacon-like behavior.

The primary output of this system is not a binary verdict, but a ranked view of events and hosts that allows analysts to focus limited response time on the most suspicious activity first. Hosts exhibiting regular outbound communication patterns, small and consistent data transfers, suspicious initiating processes, or unusual destination context are surfaced more prominently for triage. While the detector performs well on the provided dataset, it is intended as a prioritization aid rather than a definitive decision engine, and all high-risk findings require follow-up investigation to confirm malicious activity.


2.2.1 Feature Engineering

Feature engineering focused on capturing behavioral patterns commonly associated with command-and-control (C2) activity rather than relying on static indicators. The features were selected based on known attacker tradecraft and observed enterprise network behavior, with the goal of providing contextual signals that help analysts distinguish automated, persistent communication from normal user-driven traffic.

A. Temporal Behavior (Beaconing Patterns)
One of the strongest indicators of C2 activity is regular, periodic communication between a compromised host and an external server. Malware often “sleeps” for a fixed interval between callbacks to reduce noise and evade detection. To capture this behavior, inter-event timing was analyzed and transformed into a feature measuring distance from common beacon intervals (for example, approximately 60 seconds). Smaller distances indicate more regular, automated behavior, while larger values are more consistent with human-driven activity such as browsing or file transfers.

B. Traffic Volume Characteristics
C2 beaconing typically involves small, consistent data exchanges rather than large or highly variable transfers. Features derived from outbound and inbound byte counts were used to capture this distinction. These volume patterns differ from benign activities such as downloads, streaming, or software updates, which tend to produce larger and more irregular traffic profiles. Consistency in traffic volume can therefore reinforce suspicion when observed alongside regular timing.

C. Network Context (Ports and Protocols)
Destination ports and protocols were treated as weak but useful contextual signals. Most enterprise traffic uses a small set of well-known ports, and attackers often deliberately blend into this normality to evade detection. However, the use of uncommon ports can still slightly increase suspicion in certain cases. Rather than treating port numbers as decisive indicators, a simple rarity-based feature was used to highlight deviations from common enterprise patterns when combined with other behavioral signals.

D. Process Context
The initiating process was treated as a high-value contextual feature. Certain built-in system utilities and scripting engines are frequently abused by attackers because they are trusted and widely available. These processes were assigned coarse risk levels to reflect their historical abuse without assuming malicious intent. Legitimate administrative activity can use the same binaries, so process context is informative but never definitive on its own and is best interpreted alongside timing and network behavior.

E. Geographic Context (GeoIP)
Destination country information was incorporated at a coarse level to provide additional triage context. Geography alone is a weak indicator due to the widespread use of cloud infrastructure, content delivery networks, and VPNs. However, aggregation at the country level can still help analysts prioritize investigations when combined with timing, volume, and process behavior, particularly when repeated communication targets a small and unusual set of destinations.

Importantly, no single feature is sufficient to identify malicious activity on its own. Each feature was designed to contribute partial evidence, with meaningful signal emerging only when multiple behavioral and contextual indicators align to suggest automated, persistent communication patterns.

2.2.2 Model Choices & Trade-offs

Two complementary modeling approaches were used to score suspected beaconing activity: a supervised classifier and an unsupervised anomaly detector. Each serves a different purpose, and neither is sufficient on its own for reliable prioritization in an enterprise environment.

Supervised Detection Model
A simple, interpretable supervised classifier was selected as the primary detection component. This model was trained on labeled examples of benign and malicious activity and produces a probabilistic score indicating how strongly an event resembles known malicious patterns. Key advantages of this approach include transparency and consistency. The probabilistic output allows analysts to reason about confidence levels rather than relying on binary decisions, and the model’s behavior can be understood in terms of the engineered features.

The primary trade-off of supervised detection is its dependence on label quality and coverage. If training labels are incomplete, biased, or synthetic, the model may appear overconfident or fail to generalize to novel attacker behavior. Supervised models are effective at recognizing previously observed patterns but are inherently limited when adversaries change tactics or deliberately mimic benign activity.

Unsupervised Anomaly Detection
To complement the supervised model, an unsupervised anomaly detector was added. This model was trained only on traffic labeled as benign and learns a baseline representation of normal behavior. Events that deviate from this baseline receive higher anomaly scores. Because this approach does not rely on malicious labels, it can surface unusual activity that was not explicitly represented in the training data.

The trade-off is that anomaly detection is noisy when used in isolation. Not all unusual behavior is malicious, and many legitimate enterprise processes can appear anomalous. As a result, anomaly scores are best treated as supporting context rather than standalone indicators.

Why Fusion Is Necessary
The final scoring approach combines supervised confidence with unsupervised anomaly signals. The supervised model provides strong discrimination based on known malicious patterns, while the anomaly detector highlights behavioral novelty. By fusing these signals, the system becomes more robust to both overconfidence in labels and blind spots in pattern recognition. This hybrid approach aligns with real-world SOC workflows, where analysts must balance confidence, context, and alert volume when prioritizing investigations.

2.2.3 Error Analysis

As with any behavioral detection system, false positives and false negatives are expected and must be understood in order to use the output effectively. Rather than aiming for perfect separation between benign and malicious activity, this system is designed to surface behavior that warrants investigation while acknowledging realistic sources of noise and adversarial evasion.

Likely False Positives
Some benign activities may be scored as higher risk due to their similarity to beacon-like behavior. Legitimate administrative automation, such as scheduled PowerShell scripts or configuration management tools, can generate regular outbound communication patterns that resemble periodic callbacks. Enterprise monitoring agents and update services may also poll external servers at fixed intervals with small data transfers. In addition, cloud-based applications or APIs with predictable polling behavior can appear anomalous when viewed in isolation. These cases highlight why process context and analyst review are essential before taking response actions.

Likely False Negatives
False negatives are possible when attackers deliberately evade the modeled behaviors. Malware that randomizes beacon intervals, uses bursty or irregular communication, or tunnels traffic through common applications such as web browsers may bypass timing-based detection. Similarly, adversaries that rely exclusively on signed binaries or well-known cloud infrastructure can blend into normal enterprise traffic. Without richer telemetry, such activity may receive lower risk scores despite being malicious.

Opportunities for Improvement
Several enhancements could improve detection fidelity in a real deployment. Incorporating longer historical windows would enable more robust assessment of temporal patterns across days or weeks. Additional enrichment, such as domain names, TLS fingerprinting, or certificate metadata, could provide stronger context for distinguishing benign cloud services from attacker-controlled infrastructure. Process command-line arguments and parent–child relationships would significantly improve process attribution. Finally, incorporating analyst feedback into periodic retraining could help the system adapt to evolving enterprise behavior and attacker techniques.

Overall, the system is intended to reduce investigative noise rather than eliminate uncertainty. Understanding its failure modes is critical to using it effectively in a real-world SOC environment.

2.3 Prioritization of Live Events

2.3.1 Scoring Live Events

To simulate a real-world triage workflow, the trained detection pipelines were applied to a set of unlabeled network events representing live telemetry. The same feature engineering, preprocessing, and scoring logic used during training was reused at inference time to ensure consistency and avoid training–inference drift.

Each event was assigned three scores: a supervised probability score reflecting similarity to known malicious patterns, an unsupervised anomaly score indicating deviation from baseline enterprise behavior, and a final fused risk score combining both signals. The fused score ranges from 0 to 1 and represents how strongly an event aligns with known command-and-control beaconing characteristics.

Because investigations are typically performed at the host level rather than the individual event level, event scores were aggregated by host. Hosts were prioritized primarily by their maximum observed risk score, with average risk and event volume used as supporting context. This approach highlights hosts that exhibit at least one highly suspicious behavior while still accounting for sustained or repeated activity.

2.3.2 Top Hosts Prioritized for Investigation

Based on aggregated risk scores, the following hosts were identified as the highest-priority candidates for analyst investigation.

Host: HOST-055  
HOST-055 generated multiple events with elevated risk scores, including at least one event with a maximum risk score of 1.0. This indicates a strong alignment with known beaconing behavior rather than an isolated anomaly. The host exhibited highly regular outbound communication combined with small, consistent data transfers. Several high-risk events were initiated by processes commonly abused for automation or persistence. This host should be prioritized for immediate investigation, including review of process trees, command-line activity, and outbound network connections. Memory acquisition and containment should be considered if malicious activity is confirmed.

Host: HOST-045  
HOST-045 produced multiple events with very high risk scores, peaking near 0.98. Although the average risk across all events is lower, the presence of multiple extreme-risk events warrants focused attention. The flagged activity showed timing regularity and constrained traffic volumes consistent with automated callbacks. Analysts should investigate the specific high-risk events, correlate them with scheduled tasks or persistence mechanisms, and review historical network activity for recurrence.

Host: HOST-134  
HOST-134 demonstrated both a high maximum risk score and an elevated mean risk across many events, suggesting persistent suspicious behavior rather than a single outlier. Repeated outbound connections exhibited consistent timing and process context associated with scripted or automated execution. The consistency of these patterns increases confidence that the behavior is not incidental. Deeper host-based analysis is recommended, including persistence checks and correlation with endpoint telemetry.

Host: HOST-120  
HOST-120 exhibited one of the highest mean risk scores among the prioritized hosts, indicating frequent moderately to highly suspicious behavior over time. Multiple events displayed consistent traffic characteristics and repeated destination patterns. This behavior aligns with low-noise beaconing designed to blend into normal traffic while maintaining persistence. Analysts should examine long-term communication patterns and consider isolating the host if additional indicators are found.

Host: HOST-104  
HOST-104 generated several events with risk scores approaching 1.0, combined with a moderate average risk across a relatively high number of events. Suspicious activity included small, periodic data exchanges and contextual indicators that deviated from enterprise baselines when viewed collectively. Investigation should focus on network connections associated with the highest-risk events and validation of the initiating processes.

2.4 Limitations & Next Steps

While the detection system performs well on the provided dataset and is effective for prioritization, several limitations must be acknowledged. The approach relies on summarized network metadata and does not incorporate deeper protocol inspection, domain-level context, or encrypted traffic fingerprints. As a result, certain benign cloud services and administrative automation tools may appear suspicious, while well-disguised malicious traffic may evade detection.

The system also assumes relatively stable attacker behavior. Adversaries that randomize beacon intervals, piggyback on legitimate applications, or shift communication patterns dynamically may reduce the effectiveness of timing- and volume-based features. Additionally, geographic indicators are inherently weak due to the prevalence of VPNs, CDNs, and cloud-hosted infrastructure.

If this system were evolved over the next three months, several enhancements would be prioritized. First, incorporating longer historical windows would enable more robust detection of low-and-slow beaconing behavior. Second, enriching network data with domain names, TLS metadata, and certificate fingerprints would significantly improve contextual discrimination. Third, deeper endpoint telemetry — including command-line arguments, parent–child process relationships, and persistence artifacts — would greatly enhance process attribution. Finally, integrating analyst feedback into periodic retraining would allow the system to adapt to both changing enterprise behavior and evolving attacker techniques.

Overall, this system should be viewed as a force multiplier for analysts rather than an autonomous decision engine. Its primary value lies in reducing investigative noise and enabling faster, more focused response to genuinely suspicious activity.
