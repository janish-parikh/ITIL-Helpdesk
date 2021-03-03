from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import KBCategory, KBItem
from .serializers import KBCategorySerializer, KBItemSerializer


@api_view(['GET'])
def index(request):
    if request.method == 'GET':
        category_list = KBCategory.objects.all()
        category_list_serializer = KBCategorySerializer(category_list, many = True)
        return Response({'kb_categories': category_list_serializer.data})
    else :
        return Response(status=405)

@api_view(['GET'])
def category(request, slug):
    if request.method == 'GET':
        category = get_object_or_404(KBCategory, slug__iexact=slug)
        items = category.kbitem_set.all()
        category_serializer = KBCategorySerializer(category)
        items_serializer = KBItemSerializer(items, many = True)
        return Response({
            'category': category_serializer.data,
            'items': items_serializer.data,
        })
    else :
        return Response(status=405)

@api_view(['GET'])
def item(request, item):
    if request.method == 'GET':
        item = get_object_or_404(KBItem, pk=item)
        items_serializer = KBItemSerializer(item)
        return Response({
            'item': items_serializer.data,
        })
    else:
        return Response(status=405)

