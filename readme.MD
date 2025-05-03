## Cyber Security of Software Systems

### Course project description
Intrusion Detection Using a Neural Network Trained on the CSE-CIC-IDS2018 Dataset

In this project, we explore the application of machine learning techniques—specifically a neural network—for detecting malicious activity in network traffic. The goal is to demonstrate how supervised learning can be used to distinguish between normal and intrusive behavior using flow-level network features.

To build and evaluate the model, we utilized a subset of the CSE-CIC-IDS2018 dataset [\[1\]](#ref1), a comprehensive and realistic dataset developed by the Canadian Institute for Cybersecurity (CIC) in collaboration with the Communications Security Establishment (CSE). The dataset simulates a real-world corporate network, complete with servers, employee machines, and attacker systems. It includes a broad range of attack types (e.g., brute-force, DDoS, infiltration, and web-based exploits) and is widely recognized in intrusion detection research for its high-quality labeled data and realistic traffic profiles.

For this project, we selected the file Friday-02-03-2018_TrafficForML_CICFlowMeter.csv, which represents one day's worth of labeled flow data. While this represents only a small portion of the full dataset (which totals approximately 7 GB), it is sufficient to demonstrate the model's effectiveness.

A binary classifier was trained using Keras in a Google Colab notebook. Despite the reduced scope, the model achieved a strong test accuracy of approximately 99.9%, showing the potential of neural networks for binary intrusion detection tasks. The project outputs include:
- A trained neural network model (.keras and .h5)
- A scikit-learn feature standardizer (.pkl)
- Test data (Xy_test.zip)
- A command-line interface (CLI) tool (cd.py) for real-time traffic capture and classification using flow-level features

The CLI tool enables practical testing and demonstration of intrusion detection. It integrates with Wireshark's dumpcap and CICFlowMeter, offering support for both live traffic capture and offline classification of .pcap or .csv flow files.

While this project is limited to binary classification and a subset of the data, it lays the foundation for more advanced systems that could detect a wider range of threats using multi-class classification or anomaly detection.

### Part I. Training a neural network
The code for training a neural network for the purpose of intrusion detection in Colab see [notebook](./colab_train_detector.ipynb). This model only detects binary labels.
Execution time for the notebook is about ~30 min. 

The classification accuracy on test data is very impressive ~99.9%. The confusion matrix is as follows (note: dur to randomness the results may vary with your execution):
| Accuracy vs epoch | Confusion matrix |
|--|--|
| ![accuracy_vs_epoch](./CIC_IDS2018/accuracy_vs_epoch.png) | ![confusion_matrix](./CIC_IDS2018/confusion_matrix.png) |

Outputs extracted from the created Google drive folder include the neural network model file for [Keras](https://keras.io/), feature standardizer for [scikit-learn](https://scikit-learn.org) and test data can be found at [CIC_IDS2018](./CIC_IDS2018/). 

Two formats are offered for Keras model ```.h5``` and ```.keras```, however the latter is used in the codes. The ```.pkl``` file is used for the feature standardizer and ```Xy_test.zip``` houses the test data (20% of the full data).

### Part II. Command Line Interface (CLI) tool
The Python file ```cd.py``` contains the command like interface runnable tool that can be used for capturing and categorizing traffic (i.e intrusion detection) as well as categorizing individual packet data and flow files. 

Before operation setting paths to ```dumpcap.exe``` from [Wireshark](https://www.wireshark.org/) and location of ```cfm.bat``` from [CICFlowMeter](https://www.researchgate.net/publication/326991554_CICFlowmeter-V40_formerly_known_as_ISCXFlowMeter_is_a_network_traffic_Bi-flow_generator_and_analyser_for_anomaly_detection_httpsgithubcomISCXCICFlowMeter) is required. 

One may also need to find out the interface id for the mandatory ```--interface``` flag. One way of finding out is to run 
```
dumpcap.exe -D
```

Example 1: *Test everything works (paths set, tools installed etc.)*
```
py -3.12 -m cd --dry-run
```


Example 2: *Capture traffic at 5 second intervals for 60 seconds*:
```
py -3.12 -m cd --duration 60s --interval 5 --interface [INTERFACE] --output-dir "./"
```

In addition to capturing a testbed of sorts is also included. The flag ```--test-input``` followed by a flow file extension with ```.csv``` e.g ```X_test.csv``` (from the [test file](./CIC_IDS2018/Xy_test.zip)) results in a lengthy output of some ~200k lines. Should the test file have ```.pcap``` extension it is first converted to a flow file and then predict is run.

Example 3: *predict labels for X_test.csv flow file from the CIC_IDS2018 dataset*:
```
py -3.12 -m cd --test-input "[path to]/X_test.csv"
```

### References 
<a name="ref1">[1]</a>: https://www.unb.ca/cic/datasets/ids-2018.html<br/>