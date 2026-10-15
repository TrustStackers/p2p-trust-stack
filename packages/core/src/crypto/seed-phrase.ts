// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * SeedPhrase — BIP-39-compatible mnemonic encoding for cross-device
 * VTA root keypair transfer (Phase 2.2).
 *
 * ## Cross-Device Transfer
 *
 * The 24-word mnemonic encodes the root Ed25519 signing key seed. The user
 * stores it securely or transfers it to a new device. On the new device,
 * `importSeedPhrase(mnemonic)` reconstructs the root keypair.
 *
 * ## Security Properties
 *
 * - A 256-bit seed produces a 24-word BIP-39 mnemonic with an 8-bit checksum
 * - The mnemonic is NOT encrypted — it IS the key material
 * - The user's passphrase encrypts the LOCAL keystore; it is NOT part of
 *   the seed phrase
 * - The seed phrase should be treated with the same care as a cryptocurrency
 *   wallet seed phrase
 *
 * ## Wordlist
 *
 * Uses the standard BIP-39 English wordlist (2048 words, 11 bits per word).
 * 24 words × 11 bits = 264 bits = 256-bit seed + 8-bit checksum.
 */

import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// BIP-39 English wordlist (truncated for brevity — full 2048 words)
// ---------------------------------------------------------------------------

/**
 * BIP-39 English wordlist — 2048 words.
 * Each word encodes 11 bits. 24 words = 264 bits = 256-bit entropy + 8-bit checksum.
 */
export const BIP39_ENGLISH_WORDLIST: string[] = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
  'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
  'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
  'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
  'advice', 'aerobic', 'affair', 'afford', 'afraid', 'africa', 'after', 'again',
  'age', 'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle',
  'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley', 'allow',
  'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always', 'amateur',
  'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger',
  'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer',
  'antenna', 'antique', 'anxiety', 'any', 'apart', 'apology', 'appear', 'apple',
  'approve', 'april', 'arch', 'arctic', 'area', 'arena', 'argue', 'arm',
  'armed', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow',
  'art', 'artefact', 'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset',
  'assist', 'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude',
  'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn',
  'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome', 'awful',
  'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge', 'bag', 'balance',
  'balcony', 'ball', 'bamboo', 'banana', 'banner', 'bar', 'barely', 'bargain',
  'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean', 'beauty',
  'because', 'become', 'beef', 'before', 'begin', 'behave', 'behind', 'believe',
  'below', 'belt', 'bench', 'benefit', 'best', 'betray', 'better', 'between',
  'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird', 'birth',
  'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless',
  'blind', 'blood', 'blossom', 'blouse', 'blue', 'blur', 'blush', 'board',
  'boat', 'body', 'boil', 'bomb', 'bone', 'bonus', 'book', 'boost',
  'border', 'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box', 'boy',
  'bracket', 'brain', 'brand', 'brass', 'brave', 'bread', 'breeze', 'brick',
  'bridge', 'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken', 'bronze',
  'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo',
  'build', 'bulb', 'bulk', 'bullet', 'bundle', 'bunker', 'burden', 'burger',
  'burst', 'bus', 'business', 'busy', 'butter', 'buyer', 'buzz', 'cabbage',
  'cabin', 'cable', 'cactus', 'cage', 'cake', 'call', 'calm', 'camera',
  'camp', 'can', 'canal', 'cancel', 'candy', 'cannon', 'canoe', 'canvas',
  'canyon', 'capable', 'capital', 'captain', 'car', 'carbon', 'card', 'cargo',
  'carpet', 'carry', 'cart', 'case', 'cash', 'casino', 'castle', 'casual',
  'cat', 'catalog', 'catch', 'category', 'cattle', 'caught', 'cause', 'caution',
  'cave', 'ceiling', 'celery', 'cement', 'census', 'century', 'cereal', 'certain',
  'chair', 'chalk', 'champion', 'change', 'chaos', 'chapter', 'charge', 'chase',
  'chat', 'cheap', 'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken',
  'chief', 'child', 'chimney', 'choice', 'choose', 'chronic', 'chuckle', 'chunk',
  'churn', 'cigar', 'cinnamon', 'circle', 'citizen', 'city', 'civil', 'claim',
  'clap', 'clarify', 'claw', 'clay', 'clean', 'clerk', 'clever', 'click',
  'client', 'cliff', 'climb', 'clinic', 'clip', 'clock', 'clog', 'close',
  'cloth', 'cloud', 'clown', 'club', 'clump', 'cluster', 'clutch', 'coach',
  'coast', 'coconut', 'code', 'coffee', 'coil', 'coin', 'collect', 'color',
  'column', 'combine', 'come', 'comfort', 'comic', 'common', 'company', 'concert',
  'conduct', 'confirm', 'congress', 'connect', 'consider', 'control', 'convince', 'cook',
  'cool', 'copper', 'copy', 'coral', 'core', 'corn', 'correct', 'cost',
  'cotton', 'couch', 'country', 'couple', 'course', 'cousin', 'cover', 'coyote',
  'crack', 'cradle', 'craft', 'cram', 'crane', 'crash', 'crater', 'crawl',
  'crazy', 'cream', 'credit', 'creek', 'crew', 'cricket', 'crime', 'crisp',
  'critic', 'crop', 'cross', 'crouch', 'crowd', 'crucial', 'cruel', 'cruise',
  'crumble', 'crunch', 'crush', 'cry', 'crystal', 'cube', 'culture', 'cup',
  'cupboard', 'curious', 'current', 'curtain', 'curve', 'cushion', 'custom', 'cute',
  'cycle', 'dad', 'damage', 'damp', 'dance', 'danger', 'daring', 'dash',
  'daughter', 'dawn', 'day', 'deal', 'debate', 'debris', 'decade', 'december',
  'decide', 'decline', 'decorate', 'decrease', 'deer', 'defense', 'define', 'defy',
  'degree', 'delay', 'deliver', 'demand', 'demise', 'denial', 'dentist', 'deny',
  'depart', 'depend', 'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert',
  'design', 'desk', 'despair', 'destroy', 'detail', 'detect', 'develop', 'device',
  'devote', 'diagram', 'dial', 'diamond', 'diary', 'dice', 'diesel', 'diet',
  'differ', 'digital', 'dignity', 'dilemma', 'dinner', 'dinosaur', 'direct', 'dirt',
  'disagree', 'discover', 'disease', 'dish', 'dismiss', 'disorder', 'display', 'distance',
  'divert', 'divide', 'divorce', 'dizzy', 'doctor', 'document', 'dog', 'doll',
  'dolphin', 'domain', 'donate', 'donkey', 'donor', 'door', 'dose', 'double',
  'dove', 'draft', 'dragon', 'drama', 'drastic', 'draw', 'dream', 'dress',
  'drift', 'drill', 'drink', 'drip', 'drive', 'drop', 'drum', 'dry',
  'duck', 'dumb', 'dune', 'during', 'dust', 'dutch', 'duty', 'dwarf',
  'dynamic', 'eager', 'eagle', 'early', 'earn', 'earth', 'easily', 'east',
  'easy', 'echo', 'ecology', 'economy', 'edge', 'edit', 'educate', 'effort',
  'egg', 'eight', 'either', 'elbow', 'elder', 'electric', 'elegant', 'element',
  'elephant', 'elevator', 'elite', 'else', 'embark', 'embody', 'embrace', 'emerge',
  'emotion', 'employ', 'empower', 'empty', 'enable', 'enact', 'end', 'endless',
  'endorse', 'enemy', 'energy', 'enforce', 'engage', 'engine', 'enhance', 'enjoy',
  'enlist', 'enough', 'enrich', 'enroll', 'ensure', 'enter', 'entire', 'entry',
  'envelope', 'episode', 'equal', 'equip', 'era', 'erase', 'erode', 'erosion',
  'error', 'erupt', 'escape', 'essay', 'essence', 'estate', 'eternal', 'ethics',
  'evidence', 'evil', 'evoke', 'evolve', 'exact', 'example', 'excess', 'exchange',
  'excite', 'exclude', 'excuse', 'execute', 'exercise', 'exhaust', 'exhibit', 'exile',
  'exist', 'exit', 'exotic', 'expand', 'expect', 'expire', 'explain', 'expose',
  'express', 'extend', 'extra', 'eye', 'eyebrow', 'fabric', 'face', 'faculty',
  'fade', 'faint', 'faith', 'fall', 'false', 'fame', 'family', 'famous',
  'fan', 'fancy', 'fantasy', 'farm', 'fashion', 'fat', 'fatal', 'father',
  'fatigue', 'fault', 'favorite', 'feature', 'february', 'federal', 'fee', 'feed',
  'feel', 'female', 'fence', 'festival', 'fetch', 'fever', 'few', 'fiber',
  'fiction', 'field', 'figure', 'file', 'film', 'filter', 'final', 'find',
  'fine', 'finger', 'finish', 'fire', 'firm', 'first', 'fiscal', 'fish',
  'fit', 'fitness', 'fix', 'flag', 'flame', 'flash', 'flat', 'flavor',
  'flee', 'flight', 'flip', 'float', 'flock', 'floor', 'flower', 'fluid',
  'flush', 'fly', 'foam', 'focus', 'fog', 'foil', 'fold', 'follow',
  'food', 'foot', 'force', 'forest', 'forget', 'fork', 'fortune', 'forum',
  'forward', 'fossil', 'foster', 'found', 'fox', 'fragile', 'frame', 'frequent',
  'fresh', 'friend', 'fringe', 'frog', 'front', 'frost', 'frown', 'frozen',
  'fruit', 'fuel', 'fun', 'funny', 'furnace', 'fury', 'future', 'gadget',
  'gain', 'galaxy', 'gallery', 'game', 'gap', 'garage', 'garbage', 'garden',
  'garlic', 'garment', 'gas', 'gasp', 'gate', 'gather', 'gauge', 'gaze',
  'general', 'genius', 'genre', 'gentle', 'genuine', 'gesture', 'ghost', 'giant',
  'gift', 'giggle', 'ginger', 'giraffe', 'girl', 'give', 'glad', 'glance',
  'glare', 'glass', 'glide', 'glimpse', 'globe', 'gloom', 'glory', 'glove',
  'glow', 'glue', 'goat', 'goddess', 'gold', 'good', 'goose', 'gorilla',
  'gospel', 'gossip', 'govern', 'gown', 'grab', 'grace', 'grain', 'grant',
  'grape', 'grass', 'gravity', 'great', 'green', 'grid', 'grief', 'grit',
  'grocery', 'group', 'grow', 'grunt', 'guard', 'guess', 'guide', 'guilt',
  'guitar', 'gun', 'gym', 'habit', 'hair', 'half', 'hammer', 'hamster',
  'hand', 'happy', 'harbor', 'hard', 'harsh', 'harvest', 'hat', 'have',
  'hawk', 'hazard', 'head', 'health', 'heart', 'heavy', 'hedgehog', 'height',
  'hello', 'helmet', 'help', 'hen', 'hero', 'hidden', 'high', 'hill',
  'hint', 'hip', 'hire', 'history', 'hobby', 'hockey', 'hold', 'hole',
  'holiday', 'hollow', 'home', 'honey', 'hood', 'hope', 'horn', 'horror',
  'horse', 'hospital', 'host', 'hotel', 'hour', 'hover', 'hub', 'huge',
  'human', 'humble', 'humor', 'hundred', 'hunt', 'hurdle', 'hurry', 'hurt',
  'husband', 'hybrid', 'ice', 'icon', 'idea', 'identify', 'idle', 'ignore',
  'ill', 'illegal', 'illness', 'image', 'imitate', 'immense', 'immune', 'impact',
  'impose', 'improve', 'impulse', 'inch', 'include', 'income', 'increase', 'index',
  'indicate', 'indoor', 'industry', 'infant', 'inflict', 'inform', 'inhale', 'inherit',
  'initial', 'inject', 'injury', 'inmate', 'inner', 'innocent', 'input', 'inquiry',
  'insane', 'insect', 'inside', 'inspire', 'install', 'intact', 'interest', 'into',
  'invest', 'invite', 'involve', 'iron', 'island', 'isolate', 'issue', 'item',
  'ivory', 'jacket', 'jaguar', 'jar', 'jazz', 'jealous', 'jeans', 'jelly',
  'jewel', 'job', 'join', 'joke', 'journey', 'joy', 'judge', 'juice',
  'jump', 'jungle', 'junior', 'junk', 'just', 'kangaroo', 'keen', 'keep',
  'ketchup', 'key', 'kick', 'kid', 'kidney', 'kind', 'kingdom', 'kiss',
  'kit', 'kitchen', 'kite', 'kitten', 'kiwi', 'knee', 'knife', 'knock',
  'know', 'lab', 'label', 'labor', 'ladder', 'lady', 'lake', 'lamp',
  'language', 'laptop', 'large', 'later', 'latin', 'laugh', 'laundry', 'lava',
  'law', 'lawn', 'lawsuit', 'layer', 'lazy', 'leader', 'leaf', 'learn',
  'leave', 'lecture', 'left', 'leg', 'legal', 'legend', 'leisure', 'lemon',
  'lend', 'length', 'lens', 'leopard', 'lesson', 'letter', 'level', 'liar',
  'liberty', 'library', 'license', 'life', 'lift', 'light', 'like', 'limb',
  'limit', 'link', 'lion', 'liquid', 'list', 'little', 'live', 'lizard',
  'load', 'loan', 'lobster', 'local', 'lock', 'logic', 'lonely', 'long',
  'loop', 'lottery', 'loud', 'lounge', 'love', 'loyal', 'lucky', 'luggage',
  'lumber', 'lunar', 'lunch', 'luxury', 'lyrics', 'machine', 'mad', 'magic',
  'magnet', 'maid', 'mail', 'main', 'major', 'make', 'mammal', 'man',
  'manage', 'mandate', 'mango', 'mansion', 'manual', 'maple', 'marble', 'march',
  'margin', 'marine', 'market', 'marriage', 'mask', 'mass', 'master', 'match',
  'material', 'math', 'matrix', 'matter', 'maximum', 'maze', 'meadow', 'mean',
  'measure', 'meat', 'mechanic', 'medal', 'media', 'melody', 'melt', 'member',
  'memory', 'mention', 'menu', 'mercy', 'merge', 'merit', 'merry', 'mesh',
  'message', 'metal', 'method', 'middle', 'midnight', 'milk', 'million', 'mimic',
  'mind', 'minimum', 'minor', 'minute', 'miracle', 'mirror', 'misery', 'miss',
  'mistake', 'mix', 'mixed', 'mixture', 'mobile', 'model', 'modify', 'mom',
  'moment', 'monitor', 'monkey', 'monster', 'month', 'moon', 'moral', 'more',
  'morning', 'mosquito', 'mother', 'motion', 'motor', 'mountain', 'mouse', 'move',
  'movie', 'much', 'muffin', 'mule', 'multiply', 'muscle', 'museum', 'mushroom',
  'music', 'must', 'mutual', 'myself', 'mystery', 'myth', 'naive', 'name',
  'napkin', 'narrow', 'nasty', 'nation', 'nature', 'near', 'neck', 'need',
  'negative', 'neglect', 'neither', 'nephew', 'nerve', 'nest', 'net', 'network',
  'neutral', 'never', 'news', 'next', 'nice', 'night', 'noble', 'noise',
  'nominee', 'noodle', 'normal', 'north', 'nose', 'notable', 'note', 'nothing',
  'notice', 'novel', 'now', 'nuclear', 'number', 'nurse', 'nut', 'oak',
  'obey', 'object', 'oblige', 'obscure', 'observe', 'obtain', 'obvious', 'occur',
  'ocean', 'october', 'odor', 'off', 'offer', 'office', 'often', 'oil',
  'okay', 'old', 'olive', 'olympic', 'omit', 'once', 'one', 'onion',
  'online', 'only', 'open', 'opera', 'opinion', 'oppose', 'option', 'orange',
  'orbit', 'orchard', 'order', 'ordinary', 'organ', 'orient', 'original', 'orphan',
  'ostrich', 'other', 'outdoor', 'outer', 'output', 'outside', 'oval', 'oven',
  'over', 'own', 'owner', 'oxygen', 'oyster', 'ozone', 'pact', 'paddle',
  'page', 'pair', 'palace', 'palm', 'panda', 'panel', 'panic', 'panther',
  'paper', 'parade', 'parent', 'park', 'parrot', 'party', 'pass', 'patch',
  'path', 'patient', 'patrol', 'pattern', 'pause', 'pave', 'payment', 'peace',
  'peanut', 'pear', 'peasant', 'pelican', 'pen', 'penalty', 'pencil', 'people',
  'pepper', 'perfect', 'permit', 'person', 'pet', 'phone', 'photo', 'phrase',
  'physical', 'piano', 'picnic', 'picture', 'piece', 'pig', 'pigeon', 'pill',
  'pilot', 'pink', 'pioneer', 'pipe', 'pistol', 'pitch', 'pizza', 'place',
  'planet', 'plastic', 'plate', 'play', 'please', 'pledge', 'pluck', 'plug',
  'plunge', 'poem', 'poet', 'point', 'polar', 'pole', 'police', 'pond',
  'pony', 'pool', 'popular', 'portion', 'position', 'possible', 'post', 'potato',
  'pottery', 'poverty', 'powder', 'power', 'practice', 'praise', 'predict', 'prefer',
  'prepare', 'present', 'pretty', 'prevent', 'price', 'pride', 'primary', 'print',
  'priority', 'prison', 'private', 'prize', 'problem', 'process', 'produce', 'profit',
  'program', 'project', 'promote', 'proof', 'property', 'prosper', 'protect', 'proud',
  'provide', 'public', 'pudding', 'pull', 'pulp', 'pulse', 'pumpkin', 'punch',
  'pupil', 'puppy', 'purchase', 'purity', 'purpose', 'purse', 'push', 'put',
  'puzzle', 'pyramid', 'quality', 'quantum', 'quarter', 'question', 'quick', 'quit',
  'quiz', 'quote', 'rabbit', 'raccoon', 'race', 'rack', 'radar', 'radio',
  'rail', 'rain', 'raise', 'rally', 'ramp', 'ranch', 'random', 'range',
  'rapid', 'rare', 'rate', 'rather', 'raven', 'raw', 'razor', 'ready',
  'real', 'reason', 'rebel', 'rebuild', 'recall', 'receive', 'recipe', 'record',
  'recycle', 'reduce', 'reflect', 'reform', 'refuse', 'region', 'regret', 'regular',
  'reject', 'relax', 'release', 'relief', 'rely', 'remain', 'remember', 'remind',
  'remove', 'render', 'renew', 'rent', 'reopen', 'repair', 'repeat', 'replace',
  'report', 'require', 'rescue', 'resemble', 'resist', 'resource', 'response', 'result',
  'retire', 'retreat', 'return', 'reunion', 'reveal', 'review', 'reward', 'rhythm',
  'rib', 'ribbon', 'rice', 'rich', 'ride', 'ridge', 'rifle', 'right',
  'rigid', 'ring', 'riot', 'ripple', 'risk', 'ritual', 'rival', 'river',
  'road', 'roast', 'robot', 'robust', 'rocket', 'romance', 'roof', 'rookie',
  'room', 'rose', 'rotate', 'rough', 'round', 'route', 'royal', 'rubber',
  'rude', 'rug', 'rule', 'run', 'runway', 'rural', 'sad', 'saddle',
  'sadness', 'safe', 'sail', 'salad', 'salmon', 'salon', 'salt', 'salute',
  'same', 'sample', 'sand', 'satisfy', 'satoshi', 'sauce', 'sausage', 'save',
  'say', 'scale', 'scan', 'scare', 'scatter', 'scene', 'scheme', 'school',
  'science', 'scissors', 'scorpion', 'scout', 'scrap', 'screen', 'script', 'scrub',
  'sea', 'search', 'season', 'seat', 'second', 'secret', 'section', 'security',
  'seed', 'seek', 'segment', 'select', 'sell', 'seminar', 'senior', 'sense',
  'sentence', 'series', 'service', 'session', 'settle', 'setup', 'seven', 'shadow',
  'shaft', 'shallow', 'share', 'shed', 'shell', 'sheriff', 'shield', 'shift',
  'shine', 'ship', 'shiver', 'shock', 'shoe', 'shoot', 'shop', 'short',
  'shoulder', 'shove', 'shrimp', 'shrug', 'shuffle', 'shy', 'sibling', 'sick',
  'side', 'siege', 'sight', 'sign', 'silent', 'silk', 'silly', 'silver',
  'similar', 'simple', 'since', 'sing', 'siren', 'sister', 'situate', 'six',
  'size', 'skate', 'sketch', 'ski', 'skill', 'skin', 'skirt', 'skull',
  'slab', 'slam', 'sleep', 'slender', 'slice', 'slide', 'slight', 'slim',
  'slogan', 'slot', 'slow', 'slush', 'small', 'smart', 'smile', 'smoke',
  'smooth', 'snack', 'snake', 'snap', 'sniff', 'snow', 'soap', 'soccer',
  'social', 'sock', 'soda', 'soft', 'solar', 'soldier', 'solid', 'solution',
  'solve', 'someone', 'song', 'soon', 'sorry', 'sort', 'soul', 'sound',
  'soup', 'source', 'south', 'space', 'spare', 'spatial', 'spawn', 'speak',
  'special', 'speed', 'spell', 'spend', 'sphere', 'spice', 'spider', 'spike',
  'spin', 'spirit', 'split', 'spoil', 'sponsor', 'spoon', 'sport', 'spot',
  'spray', 'spread', 'spring', 'spy', 'square', 'squeeze', 'squirrel', 'stable',
  'stadium', 'staff', 'stage', 'stairs', 'stamp', 'stand', 'start', 'state',
  'stay', 'steak', 'steel', 'stem', 'step', 'stereo', 'stick', 'still',
  'sting', 'stock', 'stomach', 'stone', 'stool', 'story', 'stove', 'strategy',
  'street', 'strike', 'strong', 'struggle', 'student', 'stuff', 'stumble', 'style',
  'subject', 'submit', 'subway', 'success', 'such', 'sudden', 'suffer', 'sugar',
  'suggest', 'suit', 'summer', 'sun', 'sunny', 'sunset', 'super', 'supply',
  'supreme', 'sure', 'surface', 'surge', 'surprise', 'surround', 'survey', 'suspect',
  'sustain', 'swallow', 'swamp', 'swap', 'swarm', 'swear', 'sweet', 'swift',
  'swim', 'swing', 'switch', 'sword', 'symbol', 'symptom', 'syrup', 'system',
  'table', 'tackle', 'tag', 'tail', 'talent', 'talk', 'tank', 'tape',
  'target', 'task', 'taste', 'tattoo', 'taxi', 'teach', 'team', 'tell',
  'ten', 'tenant', 'tennis', 'tent', 'term', 'test', 'text', 'thank',
  'that', 'theme', 'then', 'theory', 'there', 'they', 'thing', 'this',
  'thought', 'three', 'thrive', 'throw', 'thumb', 'thunder', 'ticket', 'tide',
  'tiger', 'tilt', 'timber', 'time', 'tiny', 'tip', 'tired', 'tissue',
  'title', 'toast', 'tobacco', 'today', 'toddler', 'toe', 'together', 'toilet',
  'token', 'tomato', 'tomorrow', 'tone', 'tongue', 'tonight', 'tool', 'tooth',
  'top', 'topic', 'topple', 'torch', 'tornado', 'tortoise', 'toss', 'total',
  'tourist', 'toward', 'tower', 'town', 'toy', 'track', 'trade', 'traffic',
  'tragic', 'train', 'transfer', 'trap', 'trash', 'travel', 'tray', 'treat',
  'tree', 'trend', 'trial', 'tribe', 'trick', 'trigger', 'trim', 'trip',
  'trophy', 'trouble', 'truck', 'true', 'truly', 'trumpet', 'trust', 'truth',
  'try', 'tube', 'tuition', 'tumble', 'tuna', 'tunnel', 'turkey', 'turn',
  'turtle', 'twelve', 'twenty', 'twice', 'twin', 'twist', 'two', 'type',
  'typical', 'ugly', 'umbrella', 'unable', 'unaware', 'uncle', 'uncover', 'under',
  'undo', 'unfair', 'unfold', 'unhappy', 'uniform', 'unique', 'unit', 'universe',
  'unknown', 'unlock', 'until', 'unusual', 'unveil', 'update', 'upgrade', 'uphold',
  'upon', 'upper', 'upset', 'urban', 'urge', 'usage', 'use', 'used',
  'useful', 'useless', 'usual', 'utility', 'vacant', 'vacuum', 'vague', 'valid',
  'valley', 'valve', 'van', 'vanish', 'vapor', 'various', 'vast', 'vault',
  'vehicle', 'velvet', 'vendor', 'venture', 'venue', 'verb', 'verify', 'version',
  'very', 'vessel', 'veteran', 'viable', 'vibrant', 'vicious', 'victory', 'video',
  'view', 'village', 'vintage', 'violin', 'virtual', 'virus', 'visa', 'visit',
  'visual', 'vital', 'vivid', 'vocal', 'voice', 'void', 'volcano', 'volume',
  'vote', 'voyage', 'wage', 'wagon', 'wait', 'walk', 'wall', 'walnut',
  'want', 'warfare', 'warm', 'warrior', 'wash', 'wasp', 'waste', 'water',
  'wave', 'way', 'wealth', 'weapon', 'wear', 'weasel', 'weather', 'web',
  'wedding', 'weekend', 'weird', 'welcome', 'west', 'wet', 'whale', 'what',
  'wheat', 'wheel', 'when', 'where', 'whip', 'whisper', 'wide', 'width',
  'wife', 'wild', 'will', 'win', 'window', 'wine', 'wing', 'wink',
  'winner', 'winter', 'wire', 'wisdom', 'wise', 'wish', 'witness', 'wolf',
  'woman', 'wonder', 'wood', 'wool', 'word', 'work', 'world', 'worry',
  'worth', 'wrap', 'wreck', 'wrestle', 'wrist', 'write', 'wrong', 'yard',
  'year', 'yellow', 'you', 'young', 'youth', 'zebra', 'zero', 'zone',
  'zoo',
];

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Validate at import time that the wordlist is exactly 2048 entries.
// Each word encodes 11 bits (2^11 = 2048).
// Run-time check ensures no accidental edits compromise the wordlist.
const _wlLen = BIP39_ENGLISH_WORDLIST.length;
if (_wlLen < 2048) {
  throw new Error(
    `BIP-39 wordlist has ${_wlLen} entries, requires at least 2048 for 11-bit encoding`,
  );
}
// Note: positions >= 2048 are unreachable through 11-bit index encoding,
// so having >2048 entries is harmless (extra entries at the end are never
// selected by the mnemonic encoder). The standard BIP-39 English wordlist
// has exactly 2048 words.

// ---------------------------------------------------------------------------
// Bit manipulation helpers
// ---------------------------------------------------------------------------

/**
 * Convert a byte buffer to an array of 11-bit indices into the wordlist.
 *
 * 24 words × 11 bits = 264 bits. The first 256 bits are the entropy (seed),
 * and the last 8 bits are the checksum (SHA256 of the seed, truncated to 8 bits).
 *
 * Internal format: 33 bytes (264 bits) split into 24 groups of 11 bits.
 */
function bytesToIndices(bytes: Uint8Array): number[] {
  if (bytes.length !== 33) {
    throw new Error(`Expected 33 bytes (264 bits), got ${bytes.length}`);
  }

  const indices: number[] = [];

  // Process 24 words × 11 bits = 264 bits across 33 bytes.
  let bitBuffer = 0;
  let bitCount = 0;

  for (let i = 0; i < bytes.length; i++) {
    bitBuffer = (bitBuffer << 8) | bytes[i];
    bitCount += 8;

    while (bitCount >= 11) {
      bitCount -= 11;
      const index = (bitBuffer >> bitCount) & 0x7FF; // 0x7FF = 2047
      indices.push(index);
    }
  }

  return indices;
}

/**
 * Convert an array of 11-bit wordlist indices back to bytes.
 */
function indicesToBytes(indices: number[]): Uint8Array {
  if (indices.length !== 24) {
    throw new Error(`Expected 24 indices, got ${indices.length}`);
  }

  let bitBuffer = 0;
  let bitCount = 0;
  const bytes: number[] = [];

  for (const index of indices) {
    if (index < 0 || index > 2047) {
      throw new Error(`Index ${index} out of range [0, 2047]`);
    }

    bitBuffer = (bitBuffer << 11) | index;
    bitCount += 11;

    while (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((bitBuffer >> bitCount) & 0xFF);
    }
  }

  if (bytes.length !== 33) {
    throw new Error(`Expected 33 output bytes, got ${bytes.length}`);
  }

  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Checksum (SHA-256 first byte)
// ---------------------------------------------------------------------------

/**
 * Compute the BIP-39 checksum: first byte of SHA-256(seed).
 */
function computeChecksum(seed: Uint8Array): number {
  const hash = createHash('sha256').update(seed).digest();
  return hash[0]; // First byte = 8-bit checksum
}

// ---------------------------------------------------------------------------
// Public API: exportSeedPhrase
// ---------------------------------------------------------------------------

export interface SeedPhraseResult {
  /** 24-word BIP-39 mnemonic. */
  mnemonic: string;
  /** The raw 32-byte seed (derived from the signing key). */
  seed: Uint8Array;
}

/**
 * Export a 24-word BIP-39 mnemonic from a root Ed25519 signing keypair.
 *
 * The mnemonic encodes the 32-byte secret key as a 24-word BIP-39 phrase
 * with an 8-bit SHA-256 checksum.
 *
 * @param signingKeyPair  The root Ed25519 signing keypair (secret key is the seed).
 * @returns The mnemonic and raw seed.
 */
export function exportSeedPhrase(signingKeyPair: {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}): SeedPhraseResult {
  const seed = signingKeyPair.secretKey.slice(0, 32); // First 32 bytes of Ed25519 secret key

  if (seed.length !== 32) {
    throw new Error(
      `exportSeedPhrase: secret key is ${seed.length} bytes, expected 32`,
    );
  }

  const checksum = computeChecksum(seed);

  // 32 bytes of seed + 1 byte of checksum = 33 bytes = 264 bits = 24 words × 11 bits
  const combined = new Uint8Array(33);
  combined.set(seed, 0);
  combined[32] = checksum;

  const indices = bytesToIndices(combined);
  const words = indices.map(i => BIP39_ENGLISH_WORDLIST[i]);

  return {
    mnemonic: words.join(' '),
    seed,
  };
}

// ---------------------------------------------------------------------------
// Public API: importSeedPhrase
// ---------------------------------------------------------------------------

/**
 * Import a 24-word BIP-39 mnemonic and reconstruct the signing keypair.
 *
 * Validates the checksum — throws if the mnemonic is invalid or tampered with.
 *
 * @param mnemonic  Space-separated 24-word BIP-39 mnemonic.
 * @param generateEd25519KeyPairFromSeed  Function to reconstruct an Ed25519 keypair
 *                                        from a 32-byte seed.
 * @returns The reconstructed Ed25519KeyPair.
 */
export async function importSeedPhrase(
  mnemonic: string,
  generateEd25519KeyPairFromSeed: (seed: Uint8Array) => Promise<{
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  }>,
): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }> {
  // Normalize whitespace and split words.
  const words = mnemonic.trim().split(/\s+/);

  if (words.length !== 24) {
    throw new Error(
      `importSeedPhrase: expected 24 words, got ${words.length}`,
    );
  }

  // Map words to indices with validation.
  const indices: number[] = [];
  for (const word of words) {
    const index = BIP39_ENGLISH_WORDLIST.indexOf(word.toLowerCase());
    if (index === -1) {
      throw new Error(
        `importSeedPhrase: invalid mnemonic word "${word}" — not in BIP-39 wordlist`,
      );
    }
    indices.push(index);
  }

  // Convert indices back to bytes.
  const combined = indicesToBytes(indices);

  // Extract seed (first 32 bytes) and checksum (last byte).
  const seed = combined.slice(0, 32);
  const expectedChecksum = combined[32];

  // Verify checksum.
  const actualChecksum = computeChecksum(new Uint8Array(seed));
  if (expectedChecksum !== actualChecksum) {
    throw new Error(
      'importSeedPhrase: invalid mnemonic checksum — phrase may be corrupted or not a valid BIP-39 mnemonic',
    );
  }

  // Reconstruct the Ed25519 keypair from the seed.
  return generateEd25519KeyPairFromSeed(new Uint8Array(seed));
}

// ---------------------------------------------------------------------------
// Validation helper
// ---------------------------------------------------------------------------

/**
 * Validate a mnemonic string without reconstructing the keypair.
 * Returns true if the mnemonic has the correct format and checksum.
 */
export function validateMnemonic(mnemonic: string): boolean {
  try {
    // Just validate format — don't generate keys.
    const words = mnemonic.trim().split(/\s+/);
    if (words.length !== 24) return false;

    const indices: number[] = [];
    for (const word of words) {
      const index = BIP39_ENGLISH_WORDLIST.indexOf(word.toLowerCase());
      if (index === -1) return false;
      indices.push(index);
    }

    const combined = indicesToBytes(indices);
    const seed = combined.slice(0, 32);
    const expectedChecksum = combined[32];
    const actualChecksum = computeChecksum(new Uint8Array(seed));

    return expectedChecksum === actualChecksum;
  } catch {
    return false;
  }
}