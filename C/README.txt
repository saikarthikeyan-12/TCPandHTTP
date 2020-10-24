Check Whether you are in Directory C and the files http_1080.pcap, tcap_1081.pcap, tcap_1082.pcap are present
Here there are 3 python files:
	1. analysis_pcap_http.py
	2. analysis_pcap_http1081.py
	3. analysis_pcap_http1082.py


1. If you want to capture the HTTP packets for portnumber 1080, python analysis_pcap_http.py
2. If you want to capture the HTTP packets for portnumber 1081. python analysis_pcap_http1081.py
3. If you want to capture the HTTP packets for portnumber 1082. python analysis_pcap_http1082.py


Input and Output
(venv) saik@saikarthikeyan:~/PycharmProjects/FCN/Kumar-Saikarthikeyan-HW2/C$ python analysis_pcap_http1081.py
The HTTP Version is
HTTP 1.1
Number of sent packets 1051
Number of Raw bytes sent 81468
The Transmission time for Port: 1081 is 15.644810199737549
(venv) saik@saikarthikeyan:~/PycharmProjects/FCN/Kumar-Saikarthikeyan-HW2/C$ python analysis_pcap_http1082.py
The HTTP Version is
HTTP 2
Number of sent packets 570
Number of Raw bytes sent 40600
The Transmission time for Port: 1082 is 5.527446985244751
