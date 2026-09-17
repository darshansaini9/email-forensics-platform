"""
ml_training_data.py
Bundled training examples for the local TF-IDF + Logistic Regression
phishing classifier (core/ml_classifier.py). Kept as plain Python data
(not a CSV/external download) so the whole ML pipeline works completely
offline with zero setup - clone the repo, run it, the classifier trains
itself on first run in under a second and is cached to disk after that.

This is intentionally a small, hand-curated dataset covering common
phishing/BEC archetypes vs. common legitimate-email archetypes. It is
NOT a substitute for a large labeled corpus (e.g. the Nazario phishing
corpus + Enron ham corpus) in a production system - see the README for
how to swap in a larger dataset without changing anything downstream.
Each entry is (text, label) where label 1 = phishing/fraudulent, 0 = legitimate.
"""

PHISHING_EXAMPLES = [
    "Urgent: your account has been suspended, verify your identity immediately or it will be permanently closed",
    "Your account has unusual activity, click here immediately to confirm your identity within 24 hours",
    "Dear customer, we detected unauthorized access to your account, please verify your password now",
    "URGENT ACTION REQUIRED: Your payment information could not be verified, update your billing details immediately",
    "Your account will be suspended in 24 hours unless you confirm your identity by clicking the link below",
    "Security alert: someone tried to log in to your account from an unrecognized device, verify now",
    "Final notice: your subscription has expired, update your payment method immediately to avoid service interruption",
    "We need you to process an urgent wire transfer today before 2 PM, this is a confidential transaction",
    "Kindly treat this as urgent, new payment instructions and change of bank details are attached",
    "Please process this payment immediately, purchase gift cards and send the codes to complete the transaction",
    "Confidential transaction, please do not discuss with anyone else in the office until finalized",
    "Congratulations, you have won a prize, claim your reward now by verifying your account details",
    "Your package could not be delivered, click here to confirm your address and pay a small redelivery fee",
    "IRS Notice: you have an outstanding tax refund, verify your bank account information to receive payment",
    "Your mailbox is almost full, click here to verify your account and increase your storage immediately",
    "We could not verify your recent transaction, login here to confirm your identity and avoid account suspension",
    "This is your final reminder to update your account, failure to respond will result in permanent deactivation",
    "Dear valued customer, your card has been charged twice, click here to dispute and verify your details",
    "Your Netflix account payment failed, update your billing information now to avoid losing access",
    "Someone has requested a password reset for your account, if this was not you click here to secure it now",
    "Act now to avoid losing access to your account, verify your credentials within the next hour",
    "Please re-enter your credentials to confirm your identity, your session has expired due to security reasons",
    "We noticed unusual login activity from a new location, confirm your identity to keep your account safe",
    "Your invoice is overdue, click the secure link to review and make payment immediately to avoid penalties",
    "This is an automated message, your account access will be restricted unless you verify your email today",
    "Dear employee, HR requires you to update your direct deposit information immediately using the attached form",
    "Please review the new payment instructions here and confirm the wire transfer has been initiated",
    "Your account information does not match our records, please verify your identity by replying with your details",
    "As part of a routine security check we need you to confirm your login credentials via the link provided",
    "Failure to respond within the next hour may cause us to lose this deal, please verify your authorization code",
    "Attention: your email storage is full, sign in immediately to avoid losing your messages permanently",
    "We have detected suspicious activity on your PayPal account, verify your information to avoid limitation",
    "Your Apple ID has been locked for security reasons, click here to unlock and verify your identity",
    "This is your bank, we need to verify your recent transaction, log in immediately using the secure link",
    "Reminder: unusual sign-in attempt blocked, confirm it was you or your account will be locked",
    "You have a new secure message waiting, login now to view important account information",
    "Your document has been shared with you, click here and sign in with your email credentials to view it",
    "Immediate action required to avoid account termination, verify your billing and shipping details now",
    "We are updating our terms of service, verify your account within 48 hours to continue using our services",
    "Your recent order requires additional verification, provide your card details to confirm the purchase",
    "Your account was locked due to suspicious activity, click here immediately to unlock and verify your identity",
    "Confirm your recovery request by clicking the link below within one hour or your account will be permanently deleted",
    "Your password has expired, click here now to create a new one or lose access to your account",
    "Verify your identity within the next 15 minutes by clicking this link to prevent permanent account closure",
    "Click here immediately to restore access, your account has been temporarily disabled pending verification",
]

# Legitimate account-security notifications that superficially resemble
# phishing vocabulary ("secure your account", "verify", "recovered") but
# are genuinely informational confirmations rather than urgent action
# demands - included specifically so the classifier learns the actual
# distinguishing pattern (informational notice vs. urgent imperative
# click-through with a threat/deadline) instead of just keyword-matching
# words like "secure" or "verify" to "phishing".
LEGITIMATE_SECURITY_NOTIFICATIONS = [
    "Your Google Account was recovered successfully, if this was not you secure your account now",
    "Your password was changed successfully, if you did not make this change please secure your account",
    "We noticed a new sign-in to your account on a Windows device, if this was not you review your account activity",
    "Your account security settings were updated successfully, no action is needed",
    "Two factor authentication was enabled for your account, thank you for keeping your account secure",
    "Your account recovery request was completed successfully, welcome back",
    "This is a confirmation that your account password has been changed as requested",
    "A new device signed into your account, if this was you no action is needed",
    "Your recent sign-in was from a new location, we just wanted to let you know",
    "This is a routine notification that your account was accessed from a new browser",
]

LEGITIMATE_EXAMPLES = [
    "Hi team, attaching the agenda for tomorrow's 10am standup, let me know if anything is missing",
    "Thanks for your email, I will review the document and get back to you by end of week",
    "The quarterly report is now available on the shared drive, please review before Friday's meeting",
    "Your order has shipped and is expected to arrive within 3 to 5 business days",
    "Reminder: the semester examination schedule has been published on the student portal",
    "Thank you for subscribing to our newsletter, here are this month's top articles",
    "Your flight confirmation for next Tuesday is attached, check-in opens 24 hours before departure",
    "Great meeting you at the conference, let's schedule a follow up call next week",
    "Here is the invoice for last month's services, payment is due within 30 days as per our agreement",
    "The office will be closed on Monday for the public holiday, normal hours resume Tuesday",
    "Congratulations on your work anniversary, thank you for five wonderful years with the team",
    "Please find attached the meeting notes from today's project sync, action items are highlighted",
    "Your subscription renewal receipt is attached for your records, thank you for being a loyal customer",
    "The library book you requested is now available for pickup at the front desk",
    "We appreciate your feedback on our product and have shared it with the engineering team",
    "Your appointment with Dr. Smith is confirmed for next Wednesday at 2pm",
    "Here's a quick recap of what we covered in today's training session, slides are attached",
    "The team lunch is scheduled for Friday at noon, let me know if you have dietary restrictions",
    "Your monthly statement is now available to view in your online banking portal",
    "Thanks for applying, we would like to schedule an interview at your earliest convenience",
    "The pull request looks good overall, left a few minor comments on the code style",
    "Welcome to the team, looking forward to working with you starting Monday",
    "Attached is the signed contract for your records, please let us know if you have any questions",
    "Just a friendly reminder that your library books are due back next week",
    "Here is the recording of yesterday's webinar in case you missed any part of it",
    "Your reservation at the restaurant is confirmed for 7pm on Saturday for four guests",
    "The new version of the app includes several bug fixes and performance improvements",
    "Thanks for the quick turnaround on the design mockups, they look great",
    "Please see the attached syllabus for this semester's course requirements and grading policy",
    "Your package was delivered today at 3:42pm and left at the front door",
    "The board meeting minutes from last week are now available for review",
    "Happy birthday from all of us at the office, hope you have a wonderful day",
    "Your gym membership renews automatically next month, no action needed on your part",
    "Attaching the vendor comparison spreadsheet we discussed in this morning's call",
    "The conference room is booked for our 3pm meeting, see you all there",
    "Thank you for your donation, your generosity helps us continue our community programs",
    "Here's the updated project timeline reflecting the changes we discussed yesterday",
    "Your car service appointment is confirmed for Thursday morning at 9am",
    "The onboarding checklist is attached, let us know if you run into any issues on day one",
    "Just checking in to see how the project is progressing, let me know if you need any support",
]


def get_training_data():
    texts = PHISHING_EXAMPLES + LEGITIMATE_EXAMPLES + LEGITIMATE_SECURITY_NOTIFICATIONS
    labels = ([1] * len(PHISHING_EXAMPLES)
              + [0] * len(LEGITIMATE_EXAMPLES)
              + [0] * len(LEGITIMATE_SECURITY_NOTIFICATIONS))
    return texts, labels
