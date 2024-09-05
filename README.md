# EDR-Attack-and-Defense


Project:


This lab is dedicated to simulating a real cyber attack and endpoint detection and response. Utilizing Eric Capuano's guide online, I will be using virtual machines to simulate the threat &amp; victim machines.
The attack machine will utilize 'Sliver' as a C2 framework to attack a Windows endpoint machine, which will be running 'LimaCharlie' as an EDR solution.

Eric Capuano's Guide: https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?utm_campaign=post&utm_medium=web

Setup
The first step to the lab is setting up both machines. The attack machine will run on Ubuntu Server, and the endpoint will be running Windows 11. In order for this lab to work smoothly Microsoft Defender should be turned off (along with other settings). I am also going to be installing Sliver on the Ubuntu machine as my primary attack tool, and setting up LimaCharlie on the Windows machine as an EDR solution. LimaCharlie will have a sensor linked to the windows machine, and will be importing sysmon logs.


Windows 11 Machine -



<img width="831" alt="Screenshot 2024-09-05 at 1 40 13 PM" src="https://github.com/user-attachments/assets/2fe260b9-6444-46b3-8464-23971170be6b">
<img width="836" alt="Screenshot 2024-09-05 at 1 40 33 PM" src="https://github.com/user-attachments/assets/82f47532-a2a0-43fb-abce-f4a60e75eaf6">

<img width="834" alt="Screenshot 2024-09-05 at 1 42 12 PM" src="https://github.com/user-attachments/assets/27210c1c-31a4-4784-a55e-b2b49116cec2">

Ubuntu Server Machine -



<img width="833" alt="Screenshot 2024-09-05 at 1 45 57 PM" src="https://github.com/user-attachments/assets/de8e2023-6c64-4d97-8853-bc7d0144f539">

The Attacks, and the Defense

The first step is to generate our payload on Sliver, and implant the malware into the Windows host machine. Then we can create a command and control session after the malware is executed on the endpoint.

<img width="838" alt="Screenshot 2024-09-05 at 1 47 17 PM" src="https://github.com/user-attachments/assets/5b7b30a0-19f8-4306-924d-628871b9b8ef">

<img width="840" alt="Screenshot 2024-09-05 at 1 47 43 PM" src="https://github.com/user-attachments/assets/6780daa0-20ac-4add-ad70-47633aba9315">

Now that we have a live session between the two machines, the attack machine can begin peeking around, checking priveleges, getting host information, and checking what type of security the host has.
<img width="827" alt="Screenshot 2024-09-05 at 1 50 28 PM" src="https://github.com/user-attachments/assets/cdb5f341-f426-48cc-a2f3-b0bbcfd71544">

<img width="793" alt="Screenshot 2024-09-05 at 1 52 18 PM" src="https://github.com/user-attachments/assets/87aafda6-237a-4f58-859c-441b58343453">


On the host machine we can look inside our LimaCharlie SIEM and see telemetry from the attacker. We can identify the payload thats running and see the IP its conn
<img width="833" alt="Screenshot 2024-09-05 at 1 54 02 PM" src="https://github.com/user-attachments/assets/2d83f33e-f477-4e69-9bba-08020522a7e0">
<img width="828" alt="Screenshot 2024-09-05 at 1 54 25 PM" src="https://github.com/user-attachments/assets/2579687d-1244-4bc2-96a9-7862cd53adb7">

We can also use LimaCharlie to scan the hash of the payload through VirusTotal; however, it will be clean since we just created the payload ourselves.

<img width="827" alt="Screenshot 2024-09-05 at 1 56 18 PM" src="https://github.com/user-attachments/assets/8b0e6dd0-7765-45dc-b1ef-4beb9bcc8342">

Now on the attack machine we can simulate an attack to steal credentials by dumping the LSASS memory. In LimaCharlie we can check the sensors, observe the telemetry, and write rules to detect the sensitive process.


<img width="830" alt="Screenshot 2024-09-05 at 1 57 56 PM" src="https://github.com/user-attachments/assets/49b71d96-14d4-4187-a927-577638db174c">


<img width="827" alt="Screenshot 2024-09-05 at 1 58 20 PM" src="https://github.com/user-attachments/assets/c56f637e-4995-4c58-908f-6a57d7fccae1">

Now instead of simply detection, we can practice using LimaCharlie to write a rule that will detect and block the attacks coming from the Sliver server. On the Ubuntu machine we can simulate parts of a ransomware attack, by attempting to delete the volume shadow copies. In LimaCharlie we can view the telemetry and then write a rule that will block the attack entirely. After we create the rule in our SIEM, the Ubuntu machine will have no luck trying the same attack again.


<img width="834" alt="Screenshot 2024-09-05 at 2 00 35 PM" src="https://github.com/user-attachments/assets/c660f56a-be53-4eb9-80c5-5c72a64d9c87">






<img width="835" alt="Screenshot 2024-09-05 at 2 01 37 PM" src="https://github.com/user-attachments/assets/d3ae6952-eb51-4be6-8e93-1b77ab4a37b7">

-DAN







