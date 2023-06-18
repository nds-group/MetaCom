# Fast Detection of Cyberattacks on the Metaverse through User-plane Inference

This repository contains the public version of the code for our work presented at the 1st IEEE International Conference on Metaverse Computing, Networking and Applications (IEEE MetaCom '23), 26-28 June 2023, Kyoto, Japan.

## Securing the Metaverse at Line Rate

<img width="731" alt="image" src="https://github.com/nds-group/MetaCom/assets/37122991/80b8c8b1-93ab-4786-90fc-61bc0099fb0d">

We propose the very first framework for the fast and automated detection of cyberattacks against metaverse IoT devices that relies on pure user-plane inference. 
Our design aligns with the internal organization of the Protocol Independent Switch Architecture (PISA), and integrates state-of-the-art strategies for mapping decision trees to switch hardware. We implemented our solution into a real testbed with off-the-shelf Intel Tofino programmable switches using _P4_ that is a domain-specific language.

By offloading the decision logic from the control plane to the data plane, and perform inference directly in P4 programmable switches, our approach lets us classify traffic for attack detection at line rate, with high throughput and very low latency, hence abiding by the requirements of metaverse applications.

## Organization of the Repository

* _Data_: It includes the information of the dataset used and a link to access training and testing sets.
* _P4_: It includes the P4 implementations for Intel Tofino switches
* Python: It includes the jupyter notebooks for training the machine learning models and obtaining performance scores, and the python scripts for generating the M/A table entries from the saved trained models.

## Use Case

To demonstrate how in-switch machine learning inference can detect and classify attacks in metaverse IoT networks at line rate, we use the ToN-IoT dataset. The information of the dataset and traces can be found in https://research.unsw.edu.au/projects/toniot-datasets.


If you need any additional information, send us an email at beyza.butun@imdea.org
