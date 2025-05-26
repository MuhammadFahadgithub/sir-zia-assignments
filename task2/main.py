import streamlit as st
import re

st.set_page_config(page_title="Password Generator Checker", page_icon="🔒")

st.title("🔐 Password Strength Checker")
st.markdown("""
## Welcome to the ultimate password strength checker! 👏  
Use this simple tool to check the strength of your password and get suggestions on how to make it stronger.  
We will give you helpful tips to create a **Strong Password** 🔒
""")

password = st.text_input("Enter your password:", type="password")

# Add a button to trigger password check
if st.button("Check Password Strength"):
    feedback = []
    score = 0

    if password:
        # Check length
        if len(password) < 8:
            feedback.append("❌ Password must be at least 8 characters long.")
        else:
            score += 1

        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("❌ Password must contain at least one uppercase letter.")

        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("❌ Password must contain at least one lowercase letter.")

        # Check for digits
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("❌ Password must contain at least one digit.")

        # Check for special characters
        if re.search(r'[@$!%*?&]', password):
            score += 1
        else:
            feedback.append("❌ Password must contain at least one special character (e.g., @$!%*?&).")

        # Password strength assessment
        st.markdown("## Strength Evaluation:")
        if score == 5:
            st.success("✅ Your Password is strong!")
        elif score >= 3:
            st.warning("🟡 Your Password is moderate! It could be stronger.")
        else:
            st.error("🔴 Your Password is weak! Please make it stronger.")

        # Feedback suggestions
        if feedback:
            st.markdown("## Improvement Suggestions:")
            for tip in feedback:
                st.write(tip)
    else:
        st.info("Please enter a password before checking.")
