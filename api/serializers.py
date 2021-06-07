from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.translation import ugettext as _
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from django.core.mail import EmailMultiAlternatives
from api import settings as helpdesk_settings

from .lib import safe_template_context, send_templated_mail
from .models import (Attachment, EmailTemplate, FollowUp, KBCategory, KBItem,
                     PreSetReply, Queue, Ticket, TicketCC, TicketChange,
                     TicketDependency, UserSettings)

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User
        fields = ('username', 'id','is_staff','email')

class EditTicketSerializer(ModelSerializer):
    class Meta:
        model = Ticket
        exclude = ('created', 'modified', 'status', 'on_hold', 'resolution', 'last_escalation', 'assigned_to')
    
    def __init__(self, *args, **kwargs):
        """
        Add any custom fields that are defined to the form
        """
        instance = kwargs.get('instance')
        super(EditTicketSerializer, self).__init__(*args, **kwargs)
    
    def save(self, *args, **kwargs):
         return super(EditTicketSerializer, self).save(*args, **kwargs)
         
class EditFollowUpSerializer(ModelSerializer):
    class Meta:
        model = FollowUp
        exclude = ('date', 'user',)

    def __init__(self, *args, **kwargs):
        """Filter not opened tickets here."""
        instance = kwargs.get("instance")
        super(EditFollowUpSerializer, self).__init__(*args, **kwargs)
        self.fields["ticket"].queryset = Ticket.objects.filter(status__in=(Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS))

class CurrentUserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'id')

class UserSettingsSerializer(serializers.Serializer):
    login_view_ticketlist = serializers.BooleanField(required=False,)

    email_on_ticket_change = serializers.BooleanField(required=False,)

    email_on_ticket_assign = serializers.BooleanField(required=False,)

    tickets_per_page = serializers.ChoiceField(
        required=False,
        choices=((10, '10'), (25, '25'), (50, '50'), (100, '100')),
    )

    use_email_as_submitter = serializers.BooleanField(
        required=False,
    )

class TicketCCSerializer(ModelSerializer):
    ''' Adds either an email address or helpdesk user as a CC on a Ticket. Used for processing POST requests. '''

    class Meta:
        model = TicketCC
        fields = '__all__'


    def __init__(self, *args, **kwargs):
        super(TicketCCSerializer, self).__init__(*args, **kwargs)
        if helpdesk_settings.HELPDESK_STAFF_ONLY_TICKET_CC:
            users = User.objects.filter(is_active=True, is_staff=True).order_by(User.USERNAME_FIELD)
        else:
            users = User.objects.filter(is_active=True).order_by(User.USERNAME_FIELD)
        self.fields['user'].queryset = users
    

class TicketCCUserSerializer(ModelSerializer):
    ''' Adds a helpdesk user as a CC on a Ticket '''

    def __init__(self, *args, **kwargs):
        super(TicketCCUserSerializer, self).__init__(*args, **kwargs)
        users = User.objects.filter(is_active=True, is_staff=True).order_by(User.USERNAME_FIELD)
        self.fields['user'].queryset = users

    class Meta:
        model = TicketCC
        exclude = ('ticket', 'email',)

class TicketCCEmailSerializer(ModelSerializer):
    ''' Adds an email address as a CC on a Ticket '''

    def __init__(self, *args, **kwargs):
        super(TicketCCEmailSerializer, self).__init__(*args, **kwargs)

    class Meta:
        model = TicketCC
        exclude = ('ticket', 'user',)

class TicketDependencySerializer(ModelSerializer):
    ''' Adds a different ticket as a dependency for this Ticket '''
    
    class Meta:
        model = TicketDependency
        exclude = ('ticket',)

class QueueSerializer(ModelSerializer):

    class Meta:
        model = Queue
        fields = ['id','title',]

class TicketSerializer(ModelSerializer):

    class Meta:
        model = Ticket
        fields = '__all__'

class TicketFormSerializer(serializers.Serializer):
    queue = serializers.ChoiceField(
        required=True,
        choices= [('', '--------')] + [(q.id, q.title) for q in Queue.objects.filter()]
    )

    submitter_email = serializers.EmailField(
        required=False,
    )

    assigned_to = serializers.ChoiceField(
        choices=(),
        required=False,
    )

    title = serializers.CharField(
        max_length=100,
        required=True
    )

    description = serializers.CharField(
        required=True,
    )

    priority = serializers.ChoiceField(
        choices=Ticket.PRIORITY_CHOICES,
        required=True,
        initial='3' 
           )

    attachment = serializers.FileField(required=False, allow_empty_file = True)

    def __init__(self, *args, **kwargs):
        super(TicketFormSerializer, self).__init__(*args, **kwargs)
    
    def _create_follow_up(self, ticket, title, user=None):
        followup = FollowUp(ticket=ticket,
                            title=title,
                            date=timezone.now(),
                            public=True,
                                comment=self.validated_data['description'],
                            )
        if user:
            followup.user = user
        return followup
    
    def _attach_files_to_follow_up(self, followup):
        files = self.validated_data['attachment']
        if files:
            files = process_attachments(followup, [files])
        return files

    @staticmethod
    def _send_messages(ticket, queue, followup, user=None):
        context = safe_template_context(ticket)
        context['comment'] = followup.comment

        messages_sent_to = []

        if ticket.submitter_email:
            send_templated_mail(
                'newticket_submitter',
                context,
                recipients=ticket.submitter_email,
                sender=queue.from_address,
                fail_silently=True,
            )
            messages_sent_to.append(ticket.submitter_email)

        if ticket.assigned_to and \
                ticket.assigned_to != user and \
                ticket.assigned_to.usersettings_helpdesk.settings.get('email_on_ticket_assign', False) and \
                ticket.assigned_to.email and \
                ticket.assigned_to.email not in messages_sent_to:
            send_templated_mail(
                'assigned_owner',
                context,
                recipients=ticket.assigned_to.email,
                sender=queue.from_address,
                fail_silently=True,
            )
            messages_sent_to.append(ticket.assigned_to.email)

        if queue.new_ticket_cc and queue.new_ticket_cc not in messages_sent_to:
            send_templated_mail(
                'newticket_cc',
                context,
                recipients=queue.new_ticket_cc,
                sender=queue.from_address,
                fail_silently=True,
            )
            messages_sent_to.append(queue.new_ticket_cc)

        if queue.updated_ticket_cc and \
                queue.updated_ticket_cc != queue.new_ticket_cc and \
                queue.updated_ticket_cc not in messages_sent_to:
            send_templated_mail(
                'newticket_cc',
                context,
                recipients=queue.updated_ticket_cc,
                sender=queue.from_address,
                fail_silently=True,
            )

    def save(self,user):
        queue = Queue.objects.get(id=int(self.validated_data['queue']))
        ticket = Ticket(title=self.validated_data['title'],
                        submitter_email=self.validated_data['submitter_email'],
                        created=timezone.now(),
                        status=Ticket.OPEN_STATUS,
                        queue=queue,
                        description=self.validated_data['description'],
                        priority=self.validated_data['priority'],
                        # due_date=self.validated_data['due_date'],
                        )
        if self.validated_data['assigned_to']:
            try:
                u = User.objects.get(id=self.validated_data['assigned_to'])
                ticket.assigned_to = u
            except User.DoesNotExist:
                ticket.assigned_to = None
        ticket.save()
        
        if self.validated_data['assigned_to']:
            title = _('Ticket Opened & Assigned to %(name)s') % {
                'name': ticket.get_assigned_to or _("<invalid user>")
            }
        else:
            title = _('Ticket Opened')

        followup = self._create_follow_up(
            ticket, title=str('Ticket Opened Via Web'), user=user)
        followup.save()
        context = safe_template_context(ticket)
        context['comment'] = followup.comment
        messages_sent_to = []
        sender = settings.DEFAULT_FROM_EMAIL
        if ticket.submitter_email:
            recipient = ticket.submitter_email
            subject = "Your ticket has been generated" 
            body = "We have our best experts looking on the issue and will get back to you at the earliest"
            msg = EmailMultiAlternatives(subject, body, sender, [recipient,])
            msg.send(fail_silently = False)

        # files = self._attach_files_to_follow_up(followup)
        # self._send_messages(ticket=ticket,
        #                     queue=queue,
        #                     followup=followup)

class PublicTicketSerializer(serializers.Serializer):
    queue = serializers.ChoiceField(
        required=True,
        choices= [('', '--------')] + [(q.id, q.title) for q in Queue.objects.filter(allow_public_submission=True)]
    )

    title = serializers.CharField(
        max_length=100,
        required=True
    )

    description = serializers.CharField(
        required=True,
    )

    priority = serializers.ChoiceField(
        choices=Ticket.PRIORITY_CHOICES,
        required=True,
        initial='3' 
           )

    # due_date = serializers.DateTimeField(
    #     required=False,
    # )

    attachment = serializers.FileField(required=False, allow_empty_file = True)

    submitter_email = serializers.EmailField(
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super(PublicTicketSerializer, self).__init__(*args, **kwargs)
    
    def _create_follow_up(self, ticket, title, user=None):
        followup = FollowUp(ticket=ticket,
                            title=title,
                            date=timezone.now(),
                            public=True,
                                comment=self.validated_data['description'],
                            )
        if user:
            followup.user = user
        return followup
    
    def _attach_files_to_follow_up(self, followup):
        files = self.validated_data['attachment']
        if files:
            files = process_attachments(followup, [files])
        return files


    # @staticmethod
    # def _send_messages(ticket, queue, followup, user=None):
    #     context = safe_template_context(ticket)
    #     context['comment'] = followup.comment

    #     messages_sent_to = []

    #     if ticket.submitter_email:
    #         send_templated_mail(
    #             context,
    #             recipients=ticket.submitter_email,
    #             sender=queue.from_address,
    #             fail_silently=True,
    #         )
    #         messages_sent_to.append(ticket.submitter_email)

    #     if ticket.assigned_to and \
    #             ticket.assigned_to != user and \
    #             ticket.assigned_to.usersettings_helpdesk.settings.get('email_on_ticket_assign', False) and \
    #             ticket.assigned_to.email and \
    #             ticket.assigned_to.email not in messages_sent_to:
    #         send_templated_mail(
    #             'assigned_owner',
    #             context,
    #             recipients=ticket.assigned_to.email,
    #             sender=queue.from_address,
    #             fail_silently=True,
    #         )
    #         messages_sent_to.append(ticket.assigned_to.email)

    #     if queue.new_ticket_cc and queue.new_ticket_cc not in messages_sent_to:
    #         send_templated_mail(
    #             'newticket_cc',
    #             context,
    #             recipients=queue.new_ticket_cc,
    #             sender=queue.from_address,
    #             fail_silently=True,
    #         )
    #         messages_sent_to.append(queue.new_ticket_cc)

    #     if queue.updated_ticket_cc and \
    #             queue.updated_ticket_cc != queue.new_ticket_cc and \
    #             queue.updated_ticket_cc not in messages_sent_to:
    #         send_templated_mail(
                
    #             context,
    #             recipients=queue.updated_ticket_cc,
    #             sender=queue.from_address,
    #             fail_silently=True,
    #         )

    def save(self,user):
        queue = Queue.objects.get(id=int(self.validated_data['queue']))
        ticket = Ticket(title=self.validated_data['title'],
                        submitter_email=user.email,
                        created=timezone.now(),
                        status=Ticket.OPEN_STATUS,
                        queue=queue,
                        description=self.validated_data['description'],
                        priority=self.validated_data['priority'],
                        # due_date=self.validated_data['due_date'],
                        )
        ticket.save()
        
        followup = self._create_follow_up(
            ticket, title=str('Ticket Opened Via Web'), user=user)
        followup.save()
        # files = self._attach_files_to_follow_up(followup)
        context = safe_template_context(ticket)
        context['comment'] = followup.comment
        messages_sent_to = []
        sender = settings.DEFAULT_FROM_EMAIL
        if ticket.submitter_email:
            recipient = ticket.submitter_email
            subject = "Your ticket has been generated" 
            body = "We have our best experts looking on the issue and will get back to you at the earliest"
            msg = EmailMultiAlternatives(subject, body, sender, [recipient,])
            msg.send(fail_silently = False)


class FollowUpSerializer(ModelSerializer):

    class Meta:
        model = FollowUp
        fields = '__all__'


class TicketChangeSerializer(ModelSerializer):

    class Meta:
        model = TicketChange
        fields = '__all__'


class AttachmentSerializer(ModelSerializer):

    class Meta:
        model = Attachment
        fields = '__all__'


class PreSetReplySerializer(ModelSerializer):

    class Meta:
        model = PreSetReply
        fields = '__all__'


class EmailTemplateSerializer(ModelSerializer):

    class Meta:
        model = EmailTemplate
        fields = '__all__'


class KBCategorySerializer(ModelSerializer):

    class Meta:
        model = KBCategory
        fields = '__all__'


class KBItemSerializer(ModelSerializer):

    class Meta:
        model = KBItem
        fields = '__all__'
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # The default result (access/refresh tokens)
        data = super(CustomTokenObtainPairSerializer, self).validate(attrs)
        # Custom data you want to include
        data.update({'user': self.user.username})
        # data.update({'id': self.user.id})
        data.update({'status': self.user.is_staff})
        # and everything else you want to send in the response
        return data