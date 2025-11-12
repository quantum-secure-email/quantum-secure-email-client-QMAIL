from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64
from typing import List, Dict, Optional
from datetime import datetime

class GmailService:
    def __init__(self, access_token: str, refresh_token: Optional[str] = None):
        """Initialize Gmail service with OAuth credentials"""
        self.credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=None,
            client_secret=None
        )
        self.service = build('gmail', 'v1', credentials=self.credentials)
    
    def list_messages(self, max_results: int = 50, page_token: Optional[str] = None) -> Dict:
        """List messages in inbox"""
        try:
            results = self.service.users().messages().list(
                userId='me',
                maxResults=max_results,
                pageToken=page_token
            ).execute()
            
            messages = results.get('messages', [])
            next_page_token = results.get('nextPageToken')
            
            return {
                "messages": messages,
                "next_page_token": next_page_token
            }
        except Exception as e:
            print(f"Error listing messages: {e}")
            raise
    
    def get_message(self, message_id: str) -> Dict:
        """Get a specific message by ID"""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            return self._parse_message(message)
        except Exception as e:
            print(f"Error getting message: {e}")
            raise
    
    def _parse_message(self, message: Dict) -> Dict:
        """Parse Gmail message into readable format"""
        payload = message.get('payload', {})
        headers = payload.get('headers', [])
        
        # Extract headers
        subject = self._get_header(headers, 'Subject')
        from_email = self._get_header(headers, 'From')
        to_email = self._get_header(headers, 'To')
        date_str = self._get_header(headers, 'Date')
        
        # Extract body
        body = self._get_body(payload)
        
        # Detect encryption markers
        encryption_type = self._detect_encryption(body)
        
        return {
            "id": message['id'],
            "threadId": message.get('threadId'),
            "snippet": message.get('snippet', ''),
            "subject": subject,
            "from": from_email,
            "to": to_email,
            "date": date_str,
            "body": body,
            "encryption_type": encryption_type,
            "labelIds": message.get('labelIds', [])
        }
    
    def _get_header(self, headers: List[Dict], name: str) -> str:
        """Get header value by name"""
        for header in headers:
            if header['name'].lower() == name.lower():
                return header['value']
        return ''
    
    def _get_body(self, payload: Dict) -> str:
        """Extract body from message payload"""
        if 'body' in payload and 'data' in payload['body']:
            return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain' or part['mimeType'] == 'text/html':
                    if 'data' in part['body']:
                        return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                
                # Recursive for nested parts
                if 'parts' in part:
                    body = self._get_body(part)
                    if body:
                        return body
        
        return ''
    
    def _detect_encryption(self, body: str) -> str:
        """Detect encryption type from email body"""
        if 'group_id' in body and ('ciphertext_b64' in body or 'nonce_b64' in body):
            return 'group_level2'
        elif 'otp_wrapped' in body or 'otp_sender_wrapped_b64' in body:
            return 'level3'
        elif 'kem_ct_b64' in body and 'ciphertext_b64' in body:
            return 'level2'
        else:
            return 'plain'
    
    def send_message(self, to: str, subject: str, body: str, from_email: str = 'me') -> Dict:
        """Send an email"""
        try:
            message = MIMEText(body)
            message['to'] = to
            message['subject'] = subject
            
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            
            send_message = self.service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            return send_message
        except Exception as e:
            print(f"Error sending message: {e}")
            raise
