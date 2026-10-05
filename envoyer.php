<?php
// Réception du formulaire de contact MAZ-AVA Technologies.
// Protections : champ piège (honeypot), délai minimal de remplissage, limite par adresse IP, validation stricte.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

const DESTINATAIRE = 'contact@maz-ava.fr';
const EXPEDITEUR   = 'formulaire@maz-ava.fr'; // adresse du domaine, évite le classement en spam
const DELAI_MIN_S  = 4;                        // un humain met plus de 4 s à remplir
const MAX_PAR_HEURE = 5;                       // envois max par IP et par heure

function reponse($ok, $msg, $code = 200) {
    http_response_code($code);
    echo json_encode(['ok' => $ok, 'message' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') reponse(false, 'Méthode non autorisée.', 405);

// Même origine uniquement
$origine = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origine !== '') {
    $h = parse_url($origine, PHP_URL_HOST);
    $mien = preg_replace('/^www\./', '', preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? ''));
    if (preg_replace('/^www\./', '', (string)$h) !== $mien) reponse(false, 'Origine refusée.', 403);
}

function nettoyer($v, $max) {
    $v = trim((string)$v);
    $v = str_replace("\0", '', $v);
    return mb_substr($v, 0, $max);
}
function sans_saut($v) { return preg_replace('/[\r\n]+/', ' ', $v); } // anti injection d'en-têtes

// Anti-bot : champ piège rempli = robot (réponse « ok » volontairement trompeuse)
if (!empty($_POST['site_web'])) reponse(true, 'Merci, votre demande a bien été envoyée.');
$duree_ms = (int)($_POST['t'] ?? 0); // durée de remplissage mesurée côté navigateur
if ($duree_ms < DELAI_MIN_S * 1000) reponse(false, 'Envoi trop rapide, merci de réessayer.', 429);

// Limite par IP
$ip = $_SERVER['REMOTE_ADDR'] ?? 'x';
$fichier = sys_get_temp_dir() . '/mazava_' . md5($ip) . '.json';
$hist = is_file($fichier) ? (json_decode(@file_get_contents($fichier), true) ?: []) : [];
$hist = array_values(array_filter($hist, function ($t) { return $t > time() - 3600; }));
if (count($hist) >= MAX_PAR_HEURE) reponse(false, "Trop de demandes depuis votre connexion. Écrivez-nous à " . DESTINATAIRE . '.', 429);

$nom = sans_saut(nettoyer($_POST['nom'] ?? '', 80));
$prenom = sans_saut(nettoyer($_POST['prenom'] ?? '', 80));
$mail = sans_saut(nettoyer($_POST['mail'] ?? '', 120));
$objet = sans_saut(nettoyer($_POST['objet'] ?? 'Demande de contact', 80));
$message = nettoyer($_POST['message'] ?? '', 5000);

if ($nom === '' || $prenom === '' || $message === '' || !filter_var($mail, FILTER_VALIDATE_EMAIL)) {
    reponse(false, 'Merci de renseigner tous les champs avec une adresse e-mail valide.', 422);
}

$sujet = '[Site MAZ-AVA] ' . $objet . ' - ' . $prenom . ' ' . $nom;
$corps = "Nouvelle demande reçue depuis maz-ava.fr\n\n"
       . "Type : $objet\nNom : $nom\nPrénom : $prenom\nE-mail : $mail\n"
       . "Date : " . date('d/m/Y H:i') . "\n\n--- Message ---\n$message\n";

$entetes = "From: MAZ-AVA site <" . EXPEDITEUR . ">\r\n"
         . "Reply-To: $prenom $nom <$mail>\r\n"
         . "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n";
$sujet_enc = '=?UTF-8?B?' . base64_encode($sujet) . '?=';

if (!@mail(DESTINATAIRE, $sujet_enc, $corps, $entetes, '-f' . EXPEDITEUR)) {
    reponse(false, "L'envoi a échoué. Écrivez-nous à " . DESTINATAIRE . '.', 500);
}
$hist[] = time();
@file_put_contents($fichier, json_encode($hist), LOCK_EX);
reponse(true, 'Merci, votre demande a bien été envoyée. Nous vous répondons rapidement.');
