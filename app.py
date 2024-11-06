import streamlit as st
import tempfile
import os
import time
import requests

# API Key and Endpoint
API_KEY = '6c35618b25287880e25144165a3c14263ff1069a9cd308c46ce45edcda3eac1e'
VT_ENDPOINT = "https://www.virustotal.com/api/v3/files"

# Warm Greeting and Check-in
st.title("Cyber Virus Scanner Bot 🤖")
st.write("Hey there! 😊 How are you feeling today? I’m here to make sure your files are safe and secure.")

user_feeling = st.text_input("How are you doing?")  # Taking user's feeling input
if user_feeling:
    st.write(f"Aw, I’m here for you! 💪 Let’s make sure nothing’s bringing you down—especially not any nasty viruses!")

    # Explain Viruses and Protection Tips
    st.subheader("Understanding Viruses 🦠")
    st.write("""
    Viruses are malicious programs designed to disrupt, damage, or gain unauthorized access to systems and data. They are like 
    digital germs that spread through infected files or systems. Let’s break it down in more detail:

    ### How Viruses Work
    A virus works by attaching itself to a legitimate program or file. When that file is executed, the virus is activated and 
    starts spreading. They can copy themselves into other files, email addresses, and systems, eventually causing chaos in your 
    device or network. Once the virus spreads, it might:
    - **Delete files**: Imagine losing precious photos or documents.
    - **Corrupt files**: Important files could be unreadable or destroyed.
    - **Steal sensitive information**: Your personal details, passwords, or even bank info could be at risk.
    - **Slow down your system**: The virus consumes your device's resources, making it run slower.
    
    Viruses can spread through infected downloads, email attachments, compromised websites, and even physical media like USB drives.

    ### Protection Tips Against Viruses
    - **Keep Software Updated**: Regular software updates patch security vulnerabilities, which helps protect your system from viruses.
    - **Use a Reliable Antivirus Program**: Anti-virus software scans files for malicious code, preventing viruses from infiltrating your system.
    - **Be Careful with Downloads**: Avoid downloading software or files from untrustworthy websites or emails.
    - **Backup Important Data**: Always have a backup of your critical files in case the virus causes damage.
    - **Use Firewalls**: A firewall is like a digital security guard that blocks unauthorized access to your device or network.

    The more aware and cautious you are, the harder it is for viruses to sneak in. 😎
    """)

    # Ask if user wants to know about malware
    if st.button("Want to learn some cool facts about malware?"):
        st.subheader("Malware 101 🕵️‍♂️")
        st.write("""
        Malware is a catch-all term for any malicious software, and it’s like a group of evil digital entities out to harm your device. 
        Let's take a closer look at different types of malware:

        ### Types of Malware:
        
        - **Viruses**: 
        Viruses are programs that attach themselves to a legitimate file or software. They can spread across systems and cause major 
        disruptions, from deleting important files to corrupting your data. A virus needs a host to attach itself to, like an innocent-looking file or email attachment.

        - **Worms**: 
        Unlike viruses, worms don’t need a host program. They’re able to self-replicate and spread on their own. A worm will often exploit security flaws in a network or system, spreading across the internet like wildfire. 
        One example of a worm is the **Conficker Worm**, which infected millions of computers back in 2008.

        - **Trojans**: 
        A Trojan is malware disguised as legitimate software. It often tricks users into downloading it by appearing as a helpful program. Once installed, it can allow hackers to remotely control your device, steal sensitive information, or install other malicious software. Famous examples include the **Emotet Trojan**, which spreads via phishing emails.
        
        - **Spyware**: 
        Spyware is software that secretly monitors and collects your personal data without your consent. It can track your browsing habits, capture keystrokes, and steal personal information like passwords and credit card numbers. Spyware is often bundled with free software you download from shady sources. 
        Examples: **Keyloggers** (which record every keystroke you type), **Adware** (which collects your browsing data to show targeted ads).
        
        - **Ransomware**: 
        Ransomware is one of the nastiest types of malware. It encrypts your files and demands a ransom in exchange for the decryption key. If you don't pay, your data is lost. 
        - **WannaCry**, which hit in 2017, affected hundreds of thousands of devices worldwide, demanding a ransom in Bitcoin.

        - **Adware**: 
        Adware is a form of malware that bombards you with unwanted ads. While it may not be as malicious as some of the others, it can slow down your device and compromise your privacy by collecting personal data to target you with more ads.

        ### How Malware Gets In:
        Malware often sneaks in via email attachments, compromised software, suspicious websites, or infected USB drives. Cybercriminals often use **phishing** tactics to get you to click on malicious links or download infected files. You might even see malware hidden in online ads (known as **malvertising**).

        ### How to Protect Yourself from Malware:
        - **Use Antivirus Software**: Modern antivirus programs can detect and remove malware before it does damage.
        - **Don’t Click on Suspicious Links**: Avoid clicking on email links or pop-ups from unknown sources.
        - **Keep Backups**: Ransomware can lock up your files, but if you have a backup, you can restore your data without paying the ransom.
        - **Keep Your System Updated**: Updates patch vulnerabilities in software that malware can exploit.
        
        Cool stuff, right? Now, ready to upload a file for scanning? 😎
        """)

# File Uploader and Virus Scan
uploaded_file = st.file_uploader("Upload a file to scan for viruses:", type=["exe", "zip", "pdf", "docx", "jpg", "jpeg"])

if uploaded_file is not None:
    st.write(f"Scanning the file: {uploaded_file.name}...")

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name
        temp_file.write(uploaded_file.getbuffer())

    try:
        with open(temp_file_path, 'rb') as file:
            headers = {
                "x-apikey": API_KEY
            }
            files = {
                'file': file
            }
            response = requests.post(VT_ENDPOINT, headers=headers, files=files)
            response.raise_for_status()
            scan_result = response.json()

        # Display the API response
        st.write("API Response:", scan_result)

        # Check scan result
        if scan_result.get('data'):
            st.success("No virus detected! The file is safe to use.")
        else:
            st.error(f"Virus detected! {scan_result.get('verbose_msg', 'No additional information available')}")
    except requests.exceptions.RequestException as e:
        st.error(f"Error communicating with VirusTotal API: {e}")
    except Exception as e:
        st.error(f"Unexpected error: {e}")

    # File cleanup
    time.sleep(5)
    try:
        os.remove(temp_file_path)
    except PermissionError:
        st.warning("File still in use. Retrying in 2 seconds...")
        time.sleep(2)
        try:
            os.remove(temp_file_path)
        except Exception as e:
            st.error(f"Unable to delete temporary file: {e}")
