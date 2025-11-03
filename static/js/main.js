document.addEventListener('DOMContentLoaded', function () {
    // Highlight.js – syntax highlighting
    if (typeof hljs !== 'undefined') {
        hljs.highlightAll();
    }

    // Botão de copiar código
    document.querySelectorAll('pre').forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-code-btn';
        button.textContent = 'Copiar';
        button.onclick = () => {
            const code = block.querySelector('code').innerText;
            navigator.clipboard.writeText(code).then(() => {
                button.textContent = 'Copiado!';
                setTimeout(() => button.textContent = 'Copiar', 2000);
            });
        };
        block.appendChild(button);
    });

    // Validação de formulário de contato (opcional)
    const contactForm = document.querySelector('form[action="/contact"]');
    if (contactForm) {
        contactForm.addEventListener('submit', function (e) {
            const email = contactForm.querySelector('[name="email"]').value;
            if (!email.includes('@')) {
                e.preventDefault();
                alert('Por favor, insira um e-mail válido.');
            }
        });
    }
});