"use strict";

const FRASE =
  "Tenho o conector BatataSwap. No começo de uma conversa sobre um projeto conhecido, ou quando eu disser 'retomar', use `buscar_contexto` e `ler_conversa`. Quando eu disser 'passagem' ou no fim de uma tarefa, use `salvar_contexto` e `anexar_mensagens`.";

const FERRAMENTAS = [
  ["salvar_contexto", "No fim de cada tarefa e sempre que você disser \"passagem\". Salva uma versão nova; nunca apaga as antigas."],
  ["buscar_contexto", "Quando você disser \"retomar\" ou no começo de uma conversa sobre um projeto conhecido."],
  ["listar_projetos", "Antes de buscar ou ler conversa, se não souber o nome exato do projeto."],
  ["buscar", "Quando você perguntar \"o que a gente decidiu sobre X\". Busca simples por texto."],
  ["registrar_preferencia", "Quando você disser uma preferência geral, que vale para todos os projetos."],
  ["anexar_mensagens", "Na passagem, junto com salvar_contexto, para guardar as mensagens da conversa em lotes."],
  ["ler_conversa", "No retomar, quando houver conversa salva. Devolve o fio com quem registrou cada fala."],
  ["apagar", "Só se você pedir. Manda para a lixeira (30 dias para restaurar), em duas chamadas."],
];

function fillStatus() {
  const box = document.getElementById("status");
  clear(box);
  box.append(el("span", { class: "dot wait" }), el("span", { text: "Verificando…" }));
  fetchSaude().then((s) => {
    clear(box);
    if (s.naoConfigurado) {
      box.append(el("span", { class: "dot bad" }), el("span", { text: "Servidor não configurado" }));
    } else if (s.online) {
      box.append(
        el("span", { class: "dot ok" }),
        el("span", { text: "Online" }),
        el("span", { class: "mono muted", text: s.versao ? "v" + s.versao : "" }),
      );
    } else {
      box.append(el("span", { class: "dot bad" }), el("span", { text: "Offline" }));
    }
  });
}

function fillTools() {
  const body = document.getElementById("tools-body");
  for (const [nome, quando] of FERRAMENTAS) {
    body.append(
      el("tr", null, [
        el("th", { scope: "row" }, [el("code", { text: nome })]),
        el("td", { text: quando }),
      ]),
    );
  }
}

function fillConnect() {
  const copyUrl = document.getElementById("copy-url");
  if (NOT_CONFIGURED) {
    document.getElementById("mcp-url").textContent = "Servidor não configurado";
    copyUrl.disabled = true;
    return;
  }
  const url = API_BASE + "/mcp";
  document.getElementById("mcp-url").textContent = url;
  wireCopy(copyUrl, () => url);
}

function wireCopy(btn, getText) {
  const original = btn.textContent;
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
      btn.textContent = "Copiado";
    } catch (e) {
      btn.textContent = "Não deu para copiar";
    }
    setTimeout(() => {
      btn.textContent = original;
    }, 1800);
  });
}

fillStatus();
fillTools();
fillConnect();
document.getElementById("frase").textContent = FRASE;
wireCopy(document.getElementById("copy-frase"), () => FRASE);
loginClick(document.getElementById("entrar"));
loginClick(document.getElementById("entrar2"));
if (NOT_CONFIGURED) {
  document.getElementById("entrar").disabled = true;
  document.getElementById("entrar2").disabled = true;
}
