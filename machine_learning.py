import torch
from transformers import GPT2Tokenizer, GPT2LMHeadModel


def generate_description(text1, text2, model, tokenizer, max_length=100):
    # Combine the texts with a connector phrase that suits your needs
    input_text = f"{text1} and {text2}"

    # Encode the input text to tensor
    encoded_input = tokenizer.encode(input_text, return_tensors='pt')

    # Generate output from the model
    output_sequences = model.generate(
        input=encoded_input,
        max_length=max_length,
        temperature=0.7,
        num_return_sequences=1
    )

    # Decode the output to text
    generated_text = tokenizer.decode(output_sequences[0], skip_special_tokens=True)
    return generated_text


# Load pre-trained model and tokenizer
tokenizer = GPT2Tokenizer.from_pretrained('gpt2')
model = GPT2LMHeadModel.from_pretrained('gpt2')

# Example texts
text1 = "The small coffee shop offers a cozy, warm environment with vintage decor."
text2 = "A quaint cafe with old-fashioned decorations and a welcoming atmosphere."

# Generate new description
new_description = generate_description(text1, text2, model, tokenizer)
print(new_description)