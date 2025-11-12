from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from models import User, OAuthToken
from dependencies import get_current_user, get_valid_oauth_token
from gmail_service import GmailService

router = APIRouter(prefix="/api/inbox", tags=["inbox"])

@router.get("")
async def get_inbox(
    max_results: int = 50,
    page_token: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    oauth_token: OAuthToken = Depends(get_valid_oauth_token)
):
    """Get user's Gmail inbox"""
    try:
        gmail = GmailService(
            access_token=oauth_token.access_token,
            refresh_token=oauth_token.refresh_token
        )
        
        # List messages
        result = gmail.list_messages(max_results=max_results, page_token=page_token)
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
            "total": len(messages)
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
