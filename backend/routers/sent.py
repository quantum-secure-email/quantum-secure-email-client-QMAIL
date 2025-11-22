"""
Sent Emails Route
Fetches user's sent emails from Gmail
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import base64
from email import message_from_bytes
from datetime import datetime

from database import get_db
from models import User, OAuthToken
from dependencies import get_current_user, get_valid_oauth_token

router = APIRouter(prefix="/api/sent", tags=["sent"])


def parse_email_body(payload):
    """Extract email body from Gmail message payload"""
    body = ""
    
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                if 'data' in part['body']:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                    break
            elif part['mimeType'] == 'text/html' and not body:
                if 'data' in part['body']:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
    elif 'body' in payload and 'data' in payload['body']:
        body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
    
    return body


def detect_encryption_level(body: str) -> int:
    """Detect encryption level from email body"""
    if 'kem_ct_b64:' in body and 'ciphertext_b64:' in body:
        return 2
    if 'otp_key_id:' in body and 'xor_ciphertext_b64:' in body:
        return 3
    return 1


@router.get("")
async def get_sent_emails(
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """
    Fetch sent emails from Gmail
    Returns list of sent emails with encryption level detection
    """
    try:
        # Build Gmail service
        creds = Credentials(
            token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=oauth_token.client_id if hasattr(oauth_token, 'client_id') else None,
            client_secret=oauth_token.client_secret if hasattr(oauth_token, 'client_secret') else None
        )
        
        service = build('gmail', 'v1', credentials=creds)
        
        # Query sent emails
        results = service.users().messages().list(
            userId='me',
            q='in:sent',
            maxResults=50
        ).execute()
        
        messages = results.get('messages', [])
        
        sent_emails = []
        
        for msg in messages:
            try:
                # Get full message
                message = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='full'
                ).execute()
                
                headers = message['payload']['headers']
                
                # Extract headers
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(no subject)')
                to = next((h['value'] for h in headers if h['name'].lower() == 'to'), '')
                date_str = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
                
                # Parse email body
                body = parse_email_body(message['payload'])
                
                # Detect encryption level
                encryption_level = detect_encryption_level(body)
                
                # Create snippet (first 100 chars, remove encryption markers)
                snippet = body[:100].replace('🔐', '').replace('═', '').strip()
                
                sent_emails.append({
                    'id': msg['id'],
                    'to': to,
                    'subject': subject,
                    'snippet': snippet,
                    'date': date_str,
                    'encryption_level': encryption_level
                })
                
            except Exception as e:
                print(f"Error parsing message {msg['id']}: {e}")
                continue
        
        return {
            'emails': sent_emails,
            'count': len(sent_emails)
        }
        
    except Exception as e:
        print(f"Error fetching sent emails: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch sent emails: {str(e)}"
        )
