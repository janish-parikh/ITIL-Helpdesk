from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext as _
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes,authentication_classes
from rest_framework.permissions import (AllowAny, IsAdminUser, IsAuthenticated,
                                        IsAuthenticatedOrReadOnly)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet, ViewSet

from .models import (EmailTemplate, FollowUp, KBCategory, KBItem, PreSetReply,
                     Queue, Ticket, TicketCC, TicketChange, TicketDependency,
                     UserSettings)
from .serializers import (EmailTemplateSerializer, FollowUpSerializer,
                          KBCategorySerializer, KBItemSerializer,
                          PreSetReplySerializer, PublicTicketSerializer,
                          QueueSerializer, TicketCCSerializer,
                          TicketChangeSerializer, TicketFormSerializer,
                          TicketSerializer, UserSettingsSerializer)

class UserViewSet(ViewSet):
    permission_classes=[IsAuthenticated]
    authentication_classes=[JWTAuthentication]
    def create(self, request):
        serializer = PublicTicketSerializer(data=request.data)
        # serializer.fields['queue']=
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@api_view(['GET',])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def view_ticket(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not request.user.email == ticket.submitter_email and not request.user.is_superuser: 
        raise PermissionDenied()
    folloups = FollowUp.objects.filter(ticket_id = ticket_id, public=True)
    ticket_serializer = TicketSerializer(ticket)
    folloups_serializer = FollowUpSerializer(folloups, many = True)
    return Response( {
            'ticket': ticket_serializer.data,
            'followups' : folloups_serializer.data,
            'priorities': Ticket.PRIORITY_CHOICES,
            'preset_replies': PreSetReply.objects.filter(Q(queues=ticket.queue) | Q(queues__isnull=True)),
            })

class QueueViewSet(ViewSet):
    permission_classes=[IsAdminUser]
    authentication_classes=[JWTAuthentication]

    def list(self, request):
        queryset = Queue.objects.order_by('pk')
        serializer = QueueSerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        serializer = QueueSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

    def retrieve(self, request, pk=None):
        queryset = Queue.objects.all()
        item = get_object_or_404(queryset, pk=pk)
        serializer = QueueSerializer(item)
        return Response(serializer.data)

    def update(self, request, pk=None):
        try:
            item = Queue.objects.get(pk=pk)
        except Queue.DoesNotExist:
            return Response(status=404)
        serializer = QueueSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

class PreSetReplyViewSet(ViewSet):
    permission_classes=[IsAdminUser]
    authentication_classes=[JWTAuthentication]

    def list(self, request):
        queryset = PreSetReply.objects.order_by('pk')
        serializer = PreSetReplySerializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        serializer = PreSetReplySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

    def retrieve(self, request, pk=None):
        queryset = PreSetReply.objects.all()
        item = get_object_or_404(queryset, pk=pk)
        serializer = PreSetReplySerializer(item)
        return Response(serializer.data)

    def update(self, request, pk=None):
        try:
            item = PreSetReply.objects.get(pk=pk)
        except PreSetReply.DoesNotExist:
            return Response(status=404)
        serializer = PreSetReplySerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def destroy(self, request, pk=None):
        try:
            item = PreSetReply.objects.get(pk=pk)
        except PreSetReply.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)


from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer

class CustomTokenObtainPairView(TokenObtainPairView):
    # Replace the serializer with your custom
    serializer_class = CustomTokenObtainPairSerializer
