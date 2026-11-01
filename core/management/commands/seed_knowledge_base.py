from django.core.management.base import BaseCommand
from core.models import MessageKnowledgeBase, URLKnowledgeBase

class Command(BaseCommand):
    help = "Seed the knowledge base with initial fraudulent and legitimate examples."

    def handle(self, *args, **options):
        self.stdout.write("🌱 Seeding Knowledge Base...")

        fraud_messages = [
            {"content": "Dear Customer, your account has been suspended. Click http://secure-bank-verify.com to update your details within 24 hours or lose access.", "classification": "fraudulent", "fraud_category": "Phishing", "keywords": "suspended, update details, lose access, 24 hours"},
            {"content": "Congratulations! You have been selected to receive ₦5,000,000 from the CBN empowerment scheme. Send your BVN and account number to claim your prize.", "classification": "fraudulent", "fraud_category": "Advance-fee", "keywords": "congratulations, selected, CBN, BVN, claim prize"},
            {"content": "URGENT: Your package delivery failed. Pay a ₦2,500 redelivery fee via this link to receive your item: http://dhl-tracking-update.net", "classification": "fraudulent", "fraud_category": "Fake Delivery", "keywords": "urgent, delivery failed, redelivery fee, pay via link"},
            {"content": "Hello, I am a financial advisor. I can help you double your crypto investment in 48 hours with zero risk. Reply with YES to start.", "classification": "fraudulent", "fraud_category": "Crypto Scam", "keywords": "financial advisor, double crypto, 48 hours, zero risk"},
            {"content": "Your Netflix subscription has expired. Update your payment info here to avoid service interruption: http://netflix-billing-alert.com", "classification": "fraudulent", "fraud_category": "Subscription Phishing", "keywords": "subscription expired, update payment, service interruption"},
            {"content": "We noticed a suspicious login attempt on your WhatsApp. Verify your identity immediately to prevent account deletion: http://whatsapp-verify-link.com", "classification": "fraudulent", "fraud_category": "Impersonation", "keywords": "suspicious login, verify identity, prevent deletion"},
        ]

        for msg in fraud_messages:
            MessageKnowledgeBase.objects.get_or_create(content=msg["content"], defaults=msg)
        
        legit_messages = [
            {"content": "Dear Customer, a debit of ₦15,000.00 was made from your account 1234567890 at SHOPRITE on 25/10/2023. Available balance: ₦45,000.00. Do not share your PIN.", "classification": "legitimate", "keywords": "debit, available balance, do not share your PIN"},
            {"content": "Your JAMB registration is successful. Your exam date is scheduled for 15th November. Check your portal for details.", "classification": "legitimate", "keywords": "registration successful, exam date, check portal"},
            {"content": "Hello, your order #998877 has been dispatched and will be delivered today between 2 PM and 5 PM. Thank you for shopping with us.", "classification": "legitimate", "keywords": "order dispatched, delivered today, thank you"},
            {"content": "Your electricity token of ₦10,000 has been successfully purchased. Meter number: 12345678901. Token: 1122-3344-5566-7788-9900.", "classification": "legitimate", "keywords": "successfully purchased, meter number, token"},
        ]

        for msg in legit_messages:
            MessageKnowledgeBase.objects.get_or_create(content=msg["content"], defaults=msg)

        urls = [
            {"url": "http://secure-bank-verify.com", "classification": "phishing", "description": "Fake bank verification"},
            {"url": "http://dhl-tracking-update.net", "classification": "phishing", "description": "Fake courier tracking"},
            {"url": "http://netflix-billing-alert.com", "classification": "phishing", "description": "Fake billing portal"},
            {"url": "http://whatsapp-verify-link.com", "classification": "phishing", "description": "Fake messaging app verify"},
            {"url": "https://www.jamb.gov.ng", "classification": "legitimate", "description": "Official JAMB website"},
            {"url": "https://www.shoprite.com.ng", "classification": "legitimate", "description": "Official Shoprite website"},
        ]

        for u in urls:
            URLKnowledgeBase.objects.get_or_create(url=u["url"], defaults=u)

        self.stdout.write(self.style.SUCCESS("🎉 Knowledge Base seeded successfully!"))
