"""Test Authentication Module"""

from auth import auth_manager, User

print("="*60)
print("         IR-DEPI | Authentication Test")
print("="*60)
print()

# Test 1: Password hashing
print("🔐 Test 1: Password Hashing")
password = "Test@123"
hashed = auth_manager.hash_password(password)
print(f"   Original: {password}")
print(f"   Hashed: {hashed[:50]}...")
print(f"   Verify: {'✅ PASS' if auth_manager.verify_password(password, hashed) else '❌ FAIL'}")
print()

# Test 2: Token generation
print("🎫 Test 2: JWT Token Generation")
test_user = User('test_001', 'testuser', 'test@example.com', 'viewer')
token = auth_manager.generate_token(test_user)
print(f"   Token: {token[:50]}...")
decoded = auth_manager.decode_token(token)
print(f"   Decoded username: {decoded.get('username') if decoded else 'ERROR'}")
print(f"   Token valid: {'✅ PASS' if decoded else '❌ FAIL'}")
print()

# Test 3: Login with demo credentials
print("🔑 Test 3: Demo Login")
result = auth_manager.login('admin', 'Admin@123')
print(f"   Login result: {result['success']}")
if result['success']:
    print(f"   User: {result['user']['username']} ({result['user']['role']})")
    print(f"   Token generated: {'✅' if result.get('token') else '❌'}")
print()

# Test 4: Validation functions
print("✅ Test 4: Input Validation")
tests = [
    ('valid_user', auth_manager.validate_username('valid_user')),
    ('ab', auth_manager.validate_username('ab')),  # Too short
    ('valid@email.com', auth_manager.validate_email('valid@email.com')),
    ('invalid', auth_manager.validate_email('invalid')),
    ('Strong@123', auth_manager.validate_password('Strong@123')),
    ('weak', auth_manager.validate_password('weak')),
]

for value, (valid, msg) in tests:
    status = '✅' if valid else '❌'
    print(f"   {status} '{value}': {msg if msg else 'Valid'}")

print()
print("="*60)
print("✅ Authentication module tests completed!")