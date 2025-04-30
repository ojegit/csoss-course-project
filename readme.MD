## Cyber Security of Software Systems

### Course project description<br/>
*TBA*

### Neural network training for intrusion detection
The code for training a neural network with the relevant data in Colab see [notebook](./csoss_v1.pynb). Weights, standardizer and test data can be found at [CIC_IDS2018](./CIC_IDS2018/). Note that we've only used a small proportion of the CIC-IDS 2018 dataset, namely 
```Friday-02-03-2018_TrafficForML_CICFlowMeter.csv``` for training the model in order to demonstrate how such intrusion detector might work. The whole dataset is about ~7Gb and requires hours of training time even with Colab.

Two formats are offered for Keras ```.h5``` and ```.keras```. The ```.pkl``` file is for the standardized and ```Xy_test.zip``` houses the test data.

### CLI 
The tool ```cd_v1.py``` can be used for demostrating how network traffic is captured and categorized as well as testing. 

Before operation it is required to setting paths to ```dumpcap.exe``` from [Wireshark](https://www.wireshark.org/) and location of ```cfm.bat``` from [CICFlowMeter](https://www.researchgate.net/publication/326991554_CICFlowmeter-V40_formerly_known_as_ISCXFlowMeter_is_a_network_traffic_Bi-flow_generator_and_analyser_for_anomaly_detection_httpsgithubcomISCXCICFlowMeter). 

One may also need to find out the interface id for the mandatory ```--interface``` flag. One way of finding out is to run 
```
dumpcap.exe -D
```


Example: *Capture traffic at 5 second intervals for 60 seconds*:
```
py -3.12 -m cd_v1 --duration 60s --interval 5 --interface [INTERFACE] --output-dir "./"
```

What's also included is a testbed. We run predictions on the test data located at ```./CIC_IDS2018```. The flag ```--test-input``` followed by a flow file extension with ```.csv``` e.g ```X_test.csv``` (from the [test file](./CIC_IDS2018/Xy_test.zip)) results in a lengthy output of some ~200k lines. Should the test file have ```.pcap``` extension it is first converted to a flow file and then predict is run.

Example: *predict labels for X_test.csv flow file from the CIC_IDS2018 dataset*:
```
py -3.12 -m cd_v1 --test-input "[path to]/X_test.csv"
```