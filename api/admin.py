# Register your models here.
from django.contrib import admin
from django.utils.translation import ugettext_lazy as _

from .models import (Attachment, EmailTemplate, FollowUp, KBCategory, KBItem,
                     PreSetReply, Queue, Ticket, TicketCC, TicketChange,
                     TicketDependency)


@admin.register(Queue)
class QueueAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'email_address')
    prepopulated_fields = {"slug": ("title",)}

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('title', 'status', 'assigned_to', 'queue', 'hidden_submitter_email',)
    date_hierarchy = 'created'
    list_filter = ('queue', 'assigned_to', 'status')

    def hidden_submitter_email(self, ticket):
        if ticket.submitter_email:
            username, domain = ticket.submitter_email.split("@")
            username = username[:2] + "*" * (len(username) - 2)
            domain = domain[:1] + "*" * (len(domain) - 2) + domain[-1:]
            return "%s@%s" % (username, domain)
        else:
            return ticket.submitter_email
    hidden_submitter_email.short_description = _('Submitter E-Mail')


class TicketChangeInline(admin.StackedInline):
    model = TicketChange

class AttachmentInline(admin.StackedInline):
    model = Attachment

@admin.register(FollowUp)
class FollowUpAdmin(admin.ModelAdmin):
    inlines = [TicketChangeInline, AttachmentInline]
    list_display = ('ticket_get_ticket_for_url', 'title', 'date', 'ticket', 'user', 'new_status')
    list_filter = ('user', 'date', 'new_status')

    def ticket_get_ticket_for_url(self, obj):
        return obj.ticket.ticket_for_url
    ticket_get_ticket_for_url.short_description = _('Slug')


@admin.register(KBItem)
class KBItemAdmin(admin.ModelAdmin):
    list_display = ('category', 'title', 'last_updated',)
    list_display_links = ('title',)


# @admin.register(CustomField)
# class CustomFieldAdmin(admin.ModelAdmin):
#     list_display = ('name', 'label', 'data_type')


@admin.register(EmailTemplate)
class EmailTemplateAdmin(admin.ModelAdmin):
    list_display = ('template_name', 'heading')


admin.site.register(PreSetReply)
admin.site.register(KBCategory)
admin.site.register(TicketCC)
admin.site.register(TicketDependency)
