from django.http import HttpResponseBadRequest
from django.views.generic.base import ContextMixin, TemplateResponseMixin, View

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import re

@method_decorator(csrf_exempt, name='dispatch')
class MarkdownPreviewView(TemplateResponseMixin, ContextMixin, View):
    def post(self, request, *args, **kwargs):
        try:
            self.preview_data = data = request.POST['content']
        except KeyError:
            return HttpResponseBadRequest('No preview data specified.')

        return self.render_to_response(self.get_context_data(
            preview_data=data,
        ))


class ProblemMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'problem/preview.html'

    def post(self, request, *args, **kwargs):
        try:
            data = request.POST['content']

            # LaTeX 문법을 마크다운 문법으로 변환
            data = data.replace('\\InputFile', '## 입력 설명')
            data = data.replace('\\OutputFile', '## 출력 설명')

            # 예제 입력/출력은 preview에 표시하지 않음 (DB 저장만 됨)

            self.preview_data = data
        except KeyError:
            return HttpResponseBadRequest('No preview data specified.')

        return self.render_to_response(self.get_context_data(
            preview_data=data,
        ))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['MATH_ENGINE'] = 'jax'
        context['REQUIRE_JAX'] = True
        return context


class BlogMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'blog/preview.html'


class ContestMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'contest/preview.html'


class CommentMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'comments/preview.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['MATH_ENGINE'] = 'jax'
        context['REQUIRE_JAX'] = True
        return context


class FlatPageMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'flatpage-preview.html'


class ProfileMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'user/preview.html'


# class OrganizationMarkdownPreviewView(MarkdownPreviewView):
#     template_name = 'organization/preview.html'


class SolutionMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'solution-preview.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['MATH_ENGINE'] = 'jax'
        context['REQUIRE_JAX'] = True
        return context


class LicenseMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'license-preview.html'


class TicketMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'ticket/preview.html'


class DefaultMarkdownPreviewView(MarkdownPreviewView):
    template_name = 'default-preview.html'
