from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer,ResetPasswordEmailRequestSerializer,SetNewPasswordSerializer
from rest_framework.exceptions import AuthenticationFailed
from .models import User
import jwt,datetime
from django.conf import settings
from rest_framework import status,generics
from rest_framework.permissions import IsAuthenticated
from rest_framework import permissions
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str,smart_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util


# Create your views here.
class RegisterView(APIView):
    def post(self,request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
class LoginView(APIView):
    def post(self,request):
        email = request.data['email']
        password = request.data['password']
        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('user not found !')
        
        if not user.check_password(password):
            raise AuthenticationFailed('incorrect password')

        payload ={
            'id':user.id,
            'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60),
            'iat':datetime.datetime.utcnow()
        }

        token = jwt.encode(payload,'secret',algorithm='HS256').decode('utf-8')
        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response

    

class UserView(APIView):
    def get(self,request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token,'secret',algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)
    
class LogoutView(APIView):
    def post(self,request):
        response =Response()
        response.delete_cookie('jwt')
        response.data = {
            'mesaage':'success logout'
        }

        return response

# class RequestPasswordResetEmail(generics.GenericAPIView):
#     serializer_class = resetPasswordEmailRequestSerializer
#     def post (self,request):
#         serializer = self.serializer_class(data=request.data)
#         email = request.data['email']
#         if User.objects.filter(email=email).exists():
#                 user = User.objects.get(email=email)
#                 uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
#                 token = PasswordResetTokenGenerator().make_token(user)
#                 current_site = get_current_site(
#                     request=request).domain
#                 relativeLink = reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
#                 absurl = 'http://'+current_site+relativeLink
#                 email_body = 'Hello \n Use the link below to reset your password \n' + absurl
#                 data = {'email_body': email_body, 'to_email': user.email,
#                         'email_subject': 'reset your password'}
#                 Util.send_email(data)
#         return Response({'succes':'we have sent you link to reset your password'},status=status.HTTP_200_OK)

# class PasswordTokenCheckAPI(generics.GenericAPIView):
#     def get(self,request,uidb64,token):
#         pass

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    # serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        pass

        # redirect_url = request.GET.get('redirect_url')

        # try:
        #     id = smart_str(urlsafe_base64_decode(uidb64))
        #     user = User.objects.get(id=id)

        #     if not PasswordResetTokenGenerator().check_token(user, token):
        #         if len(redirect_url) > 3:
        #             return CustomRedirect(redirect_url+'?token_valid=False')
        #         else:
        #             return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        #     if redirect_url and len(redirect_url) > 3:
        #         return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
        #     else:
        #         return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        # except DjangoUnicodeDecodeError as identifier:
        #     try:
        #         if not PasswordResetTokenGenerator().check_token(user):
        #             return CustomRedirect(redirect_url+'?token_valid=False')
                    
        #     except UnboundLocalError as e:
        #         return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)



class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)