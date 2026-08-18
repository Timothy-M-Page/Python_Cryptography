import hashlib
import time


class Block:
    # A block is a collection of a data, a timestamp and the previous hash.
    def __init__(self, data: str, prev_hash: str = '') -> None:
        self.data = data
        self.timestamp = time.time()
        self.prev_hash = prev_hash

    def calculate_hash(self) -> str:
        # Chain structure comes from the hashing of the entire previous block.
        block_string = f"{self.timestamp}{self.data}{self.prev_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()


class Blockchain:
    # Define a blockchain as an empty array with a genesis block appended.
    def __init__(self) -> None:
        self.chain: list[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self) -> None:
        genesis_block = Block('Genesis Block', '0')
        self.chain.append(genesis_block)

    def add_block(self, data: str) -> None:
        # A method to add new blocks to the chain.
        last_block = self.chain[-1]
        prev_hash = last_block.calculate_hash()
        new_block = Block(data, prev_hash)
        self.chain.append(new_block)


blockchain = Blockchain()
blockchain.add_block('Block 1')
blockchain.add_block('Block 2')

for block in blockchain.chain:
    print(f'Data: {block.data}, Time: {block.timestamp}, '
          f'Previous Hash: {block.prev_hash}')
