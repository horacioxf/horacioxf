<h2> Scenario </h2>

Alonzo Spotted Weird files on his computer and informed the newly assembled SOC Team. Assessing the situation it is believed a Kerberoasting attack may have occurred in the network. It is your job to confirm the findings by analyzing the provided evidence. You are provided with: 1- Security Logs from the Domain Controller 2- PowerShell-Operational Logs from the affected workstation 3- Prefetch Files from the affected workstation

<h2>Question 1</h2>
Analyzing Domain Controller Security Logs, can you confirm the date & time when the kerberoasting activity occurred? 

Since this investigation is being done for a Windows machine, there's an event viewer log for the machine. The question is asking for kerberoasting activity in even viewer, a quick Google search tells me that the Event ID for Kerberos service ticket requests is 4769. Using this filter, I can narrow down the results using Event ID 4769. There's a ticket for the service name alonzo.spire, which is different from the other results DC01$@FORELA.LOCAL and Administrator@FORELA.LOCAL.

<img width="702" height="801" alt="image" src="https://github.com/user-attachments/assets/849f8fd1-9d18-41e0-a98a-e517bf091c52" />

<img width="703" height="832" alt="image" src="https://github.com/user-attachments/assets/d15de8fd-7567-4819-a41b-dc268ae5d3e0" />

Answer: 2024-05-20 03:18:09

<h2>Question 2</h2>
What is the Service Name that was targeted?

<img width="702" height="452" alt="image" src="https://github.com/user-attachments/assets/178f3e1f-dc4a-4edb-ab75-fb9b1503f5b6" />

Answer: MSSQLService

<h2>Question 3</h2>
It is really important to identify the Workstation from which this activity occurred. What is the IP Address of the workstation?

<img width="697" height="446" alt="image" src="https://github.com/user-attachments/assets/ba745866-82c6-4f03-aa10-f15691971e74" />

<h2>Question 4</h2>
Now that we have identified the workstation, a triage including PowerShell logs and Prefetch files is provided to you for some deeper insights so we can understand how this activity occurred on the endpoint. What is the name of the file used to Enumerate Active directory objects and possibly find Kerberoastable accounts in the network?

Filtering for Event ID 4104 (This Event ID is for PowerShell script block logging). 

<img width="700" height="280" alt="image" src="https://github.com/user-attachments/assets/89ac432e-7429-4830-94c3-049d62e8360d" />

Answer: powerview.ps1

<h2>Question 5</h2>
When was this script executed?

<img width="665" height="547" alt="image" src="https://github.com/user-attachments/assets/af11de09-98bd-444e-ba40-141ca3b98beb" />

Answer: 2024-05-21

<h2>Question 6</h2>
What is the full path of the tool used to perform the actual kerberoasting attack?

I can find this using the Files Loaded cell for the executable Rubeus.exe. The reason Ruebeus was used is cause it's an AD offensive tool. 

<img width="704" height="407" alt="image" src="https://github.com/user-attachments/assets/05415840-823b-4de8-9397-8fde28df595b" />

Answer: \USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE

<h2>Question 7</h2>
When was the tool executed to dump the credentials? 

I'm able to find this using the Last run tab.

<img width="704" height="413" alt="image" src="https://github.com/user-attachments/assets/87ae8a16-e8de-4e85-aeaa-e0784c175374" />

Answer: 2024-05-21 03:18:08 
