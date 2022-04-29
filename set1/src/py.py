from collections import Counter
import math
import string

non_alpha_weight = 10

expected = [0.082, 0.015, 0.028, 0.043, 0.13, 0.022, 0.02, 0.061, 0.07, 0.015, 0.077, 0.04, 0.024, 0.067, 0.075, 0.019, 0.0095, 0.06, 0.063, 0.091, 0.028, 0.0098, 0.024, 0.015, 0.02, 0.074, 0]

def l2_eng(input_string):
	counts = Counter(input_string)
	adjusted = [counts.get(c, 0)/len(input_string) for c in string.ascii_lowercase]
	adjusted.append(((sum(counts.get(x, 0) for x in filter(lambda c: c not in string.ascii_lowercase, counts.keys()))) / len(input_string))*non_alpha_weight)

	errors = [adjusted[i] - expected[i] for i in range(len(expected))]
	total_error = sum([e**2 for e in errors])
	return math.sqrt(total_error)


encoded_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

raw_bytes = []
for i in range(0, len(encoded_string), 2):
	raw_bytes.append(int(encoded_string[i:i+2], 16))


key = 0
min_score = 10000000
best_key = 0

while key < 0xFF:

	decoded = "".join([chr(b ^ key) for b in raw_bytes])
	
	score = l2_eng(decoded)
	print(f"key: {key} score: {score}: str: {decoded}")

	# print(f"score {score} < min_score {min_score}")

	if score < min_score:
		min_score = score
		best_key = key

	key += 1
	print(f"best_key: {best_key} best_score: {min_score}")


decoded = "".join([chr(b ^ best_key) for b in raw_bytes])

print(f"key: {best_key} score: {l2_eng(decoded)}: str: {decoded}")
