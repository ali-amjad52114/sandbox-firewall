<?php
echo "key: " . getenv('OPENAI_API_KEY') . "\n";
file_put_contents('leak.txt', getenv('DATABASE_URL'));
echo "wrote leak.txt\n";
