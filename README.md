# QMail - Quantum-Secure Email Client

A production-ready email security system that provides quantum-resistant encryption for Gmail. QMail implements a three-tier security architecture using post-quantum cryptography, enabling secure communications that remain protected even against future quantum computer attacks.

## 🔐 Features

### Multi-Level Encryption
- **Level 1 (Standard)**: Gmail's built-in TLS encryption for casual communications
- **Level 2 (Post-Quantum)**: Kyber512 + AES-256-GCM for quantum-resistant protection
- **Level 3 (Maximum Security)**: One-Time Pad with simulated Quantum Key Distribution for information-theoretic security

### Secure Communication
- **Individual Emails**: Full encryption support across all three security levels
- **Group Encryption**: Shared key distribution using post-quantum cryptography (Levels 1-2)
- **Zero-Knowledge Architecture**: Private keys never leave the client browser
- **Automatic Device Management**: Seamless key generation and registration on first login

### Gmail Integration
- **OAuth 2.0 Authentication**: Secure server-side authorization flow with automatic token refresh
- **Full Gmail Access**: Read inbox, send emails, manage labels - all through familiar Gmail interface
- **Encryption Indicators**: Visual badges showing protection level for each email

### User Experience
- **Modern Web Interface**: React-based responsive UI with TailwindCSS
- **Real-Time Decryption**: Client-side decryption with instant plaintext display
- **Group Management**: Create groups, add members, send encrypted group emails
- **Cross-Device Support**: Register multiple devices with independent encryption keys

## 🛠️ Technology Stack

### Frontend
- **React 18** + TypeScript + Vite
- **TailwindCSS** + shadcn/ui components
- **TanStack Query** for data fetching
- **IndexedDB** for secure client-side key storage

### Backend
- **FastAPI** (Python 3.11)
- **liboqs-python** for post-quantum cryptography (Kyber512)
- **SQLAlchemy** ORM with PostgreSQL
- **Google OAuth 2.0** + Gmail API
- **cryptography** library for AES-256-GCM and HKDF

### Infrastructure
- **PostgreSQL** for data persistence
- **Render.com** cloud deployment (3 separate services)
- **GitHub Actions** for CI/CD
- **Alembic** for database migrations

## 🏗️ Architecture

QMail uses a modern three-tier architecture:

```
Frontend (React SPA)
    ↓
Backend API (FastAPI)
    ↓
Database (PostgreSQL)
```

### Deployment
- **Frontend**: Static site hosting on Render
- **Backend**: Python web service with automatic scaling
- **Database**: Managed PostgreSQL instance with encrypted storage

### Security Model
- **Client-Side Key Storage**: Private keys stored in browser's IndexedDB (never transmitted)
- **Server-Side Public Keys**: Public keys stored in database for encryption operations
- **Zero-Knowledge Server**: Server cannot decrypt Level 2/3 messages
- **Forward Secrecy**: Each message uses fresh ephemeral keys

## 📊 Database Schema

- **users**: Authenticated Google users
- **oauth_tokens**: Google OAuth credentials with auto-refresh
- **devices**: User device public keys (Kyber512)
- **groups**: Group metadata for multi-user communications
- **group_members**: Junction table for group membership
- **group_keys**: Per-user encrypted group keys
- **km_store**: Pre-generated OTP keys for Level 3 encryption

## 🔑 Key Features Deep Dive

### Post-Quantum Cryptography
Uses **Kyber512**, the NIST-approved post-quantum Key Encapsulation Mechanism (KEM). Provides security against quantum computer attacks using Shor's algorithm.

### One-Time Pad (Level 3)
Implements information-theoretically secure encryption:
- Pre-generated cryptographically secure random keys
- Each key used exactly once (enforced by database)
- Simulates Quantum Key Distribution (QKD)
- Perfect secrecy guarantee

### Group Encryption
Efficient one-to-many encryption:
- Server generates shared AES-256 group key
- Key encrypted individually for each member using Kyber512
- Messages encrypted once, distributed to all members
- Zero-knowledge: server never has decrypted group key

## 🚀 Deployment

QMail is deployed on Render.com with three services:
1. **Frontend**: https://qmail-frontend.onrender.com
2. **Backend**: https://qmail-backend.onrender.com  
3. **Database**: Managed PostgreSQL instance

All services deploy automatically on push to main branch.

## 🧪 Testing

### Verified Scenarios
- ✅ Google OAuth authentication flow
- ✅ Automatic token refresh
- ✅ Level 1/2/3 encryption for individual emails
- ✅ Level 1/2 encryption for group emails
- ✅ Client-side decryption
- ✅ Multi-device support
- ✅ Group creation and management
- ✅ Cross-user communications



## 🔒 Security Highlights

- **Quantum-Resistant**: Kyber512 protects against future quantum attacks
- **Information-Theoretic Security**: OTP provides perfect secrecy for Level 3
- **Zero-Knowledge**: Server cannot decrypt user messages
- **Forward Secrecy**: Each message independently secured
- **Authenticated Encryption**: AES-GCM prevents tampering
- **Secure Token Storage**: OAuth tokens encrypted at rest
- **HTTPS Enforced**: All communications over TLS 1.3


