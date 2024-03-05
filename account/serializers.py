from rest_framework import serializers
from account.models import MyCustomUser
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyCustomUser
        fields = ['email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    #def validate(self, attrs):
        #TODO: Check password length and secure password
        #return super().validate(attrs)

    def create(self, validated_data):
        return MyCustomUser.objects.create_user(**validated_data)

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    class Meta:
        model = MyCustomUser 
        fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyCustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'mobile']

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    class Meta:
        fields = ['old_password', 'password']

    def validate(self, attrs):
        #if len(attrs['password']) < 8:
        print(f'attrs:${attrs}')
        old_password = attrs['old_password']
        new_password = attrs['password']
        if not old_password:
            raise serializers.ValidationError({'old_password': 'This field is required.'})

        if not new_password:
            raise serializers.ValidationError({'new_password': 'This field is required.'})
        user = self.context['user']
        print(f'user:{user}')
        print(old_password)
        if new_password == old_password:
            raise serializers.ValidationError("New password must be different than old password.")
        user.set_password(new_password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if MyCustomUser.objects.filter(email=email).exists():
            # Send email
            user = MyCustomUser.objects.get(email=email)
            # Generate a one-time use link for resetting password
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded id ', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password reset token: ', token)
            link = 'http://localhost:3000/api/users/password-reset/' + uid + '/' + token
            print('Password reset link: ', link)
            #send email
            return attrs
        else:
            raise serializers.ValidationError({'email': 'User with this email does not exist.'})    
        return super().validate(attrs)

