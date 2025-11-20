from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from database import get_db
from models import User, OAuthToken
from dependencies import get_current_user, get_valid_oauth_token
from gmail_service import GmailService

router = APIRouter(prefix="/api/inbox", tags=["inbox"])

# Request models
class SendEmailRequest(BaseModel):
    to: str
    subject: str
    body: str

class MarkReadRequest(BaseModel):
    message_id: str

@router.get("")
async def get_inbox(
    max_results: int = 50,
    page_token: Optional[str] = None,
    primary_only: bool = True,  # New parameter to filter primary emails
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """
    Get user's Gmail inbox
    
    Args:
        max_results: Number of emails to fetch (default: 50)
        page_token: Token for pagination
        primary_only: If True, only show Primary inbox emails (default: True)
    """
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        # List messages with primary filter
        result = gmail.list_messages(
            max_results=max_results, 
            page_token=page_token,
            primary_only=primary_only
        )
        message_ids = result['messages']
        
        # Get full details for each message
        messages = []
        for msg in message_ids:
            try:
                full_message = gmail.get_message(msg['id'])
                messages.append(full_message)
            except Exception as e:
                print(f"Error fetching message {msg['id']}: {e}")
                continue
        
        return {
            "messages": messages,
            "next_page_token": result['next_page_token'],
            "total": len(messages),
            "primary_only": primary_only
        }
        
    except Exception as e:
        print(f"Inbox error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{message_id}")
async def get_message(
    message_id: str,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """Get a specific email message"""
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        message = gmail.get_message(message_id)
        return message
        
    except Exception as e:
        print(f"Error getting message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send")
async def send_email(
    email_data: SendEmailRequest,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """
    Send an email via Gmail
    
    Request body:
        - to: Recipient email address
        - subject: Email subject
        - body: Email body (supports HTML)
    """
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        # Send the email
        result = gmail.send_message(
            to=email_data.to,
            subject=email_data.subject,
            body=email_data.body
        )
        
        return {
            "success": True,
            "message_id": result['id'],
            "thread_id": result.get('threadId'),
            "message": "Email sent successfully"
        }
        
    except Exception as e:
        print(f"Error sending email: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")


@router.post("/{message_id}/read")
async def mark_as_read(
    message_id: str,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """Mark an email as read"""
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        result = gmail.mark_as_read(message_id)
        
        return {
            "success": True,
            "message_id": message_id,
            "status": "read"
        }
        
    except Exception as e:
        print(f"Error marking as read: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{message_id}/unread")
async def mark_as_unread(
    message_id: str,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """Mark an email as unread"""
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        result = gmail.mark_as_unread(message_id)
        
        return {
            "success": True,
            "message_id": message_id,
            "status": "unread"
        }
        
    except Exception as e:
        print(f"Error marking as unread: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{message_id}/toggle-read")
async def toggle_read_status(
    message_id: str,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """Toggle read/unread status of an email"""
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        # Get current message to check if it's read or unread
        message = gmail.get_message(message_id)
        is_unread = message.get('isUnread', False)
        
        if is_unread:
            # Currently unread, mark as read
            result = gmail.mark_as_read(message_id)
            new_status = "read"
        else:
            # Currently read, mark as unread
            result = gmail.mark_as_unread(message_id)
            new_status = "unread"
        
        return {
            "success": True,
            "message_id": message_id,
            "previous_status": "unread" if is_unread else "read",
            "new_status": new_status
        }
        
    except Exception as e:
        print(f"Error toggling read status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
